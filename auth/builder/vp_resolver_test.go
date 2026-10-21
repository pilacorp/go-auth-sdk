package builder

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// vpFixture holds an issuer-signed VC token and a resolver publishing both the
// issuer's and the holder's keys.
type vpFixture struct {
	holderKeyBytes []byte
	resolver       *verificationmethod.StaticResolver
	vcToken        string
}

func newVPFixture(t *testing.T) vpFixture {
	t.Helper()
	issuer, issuerBytes := newTestKey(t)
	holder, holderBytes := newTestKey(t)
	r := newTestResolver(t, map[string]*ecdsaPub{
		testIssuerDID: &issuer.PublicKey,
		testHolderDID: &holder.PublicKey,
	})

	res, err := newTestVCBuilder(WithBuilderResolver(r)).Build(context.Background(), testVCData(),
		WithSignerOptions(signer.WithPrivateKey(issuerBytes)))
	if err != nil {
		t.Fatalf("failed to build VC: %v", err)
	}
	return vpFixture{holderKeyBytes: holderBytes, resolver: r, vcToken: res.Token}
}

func (f vpFixture) data() model.VPData {
	return model.VPData{HolderDID: testHolderDID, VCTokens: []string{f.vcToken}}
}

func newTestVPBuilder(opts ...VPBuilderConfigOption) *VPBuilder {
	return NewVPBuilder(append([]VPBuilderConfigOption{WithVPSigner(ecdsa.NewPrivSigner(nil))}, opts...)...)
}

func TestVPBuilder_Build_WithResolver(t *testing.T) {
	f := newVPFixture(t)

	result, err := newTestVPBuilder(WithVPBuilderResolver(f.resolver)).Build(context.Background(), f.data(),
		WithVPSignerOptions(signer.WithPrivateKey(f.holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if kid := jwtHeader(t, result.Token)["kid"]; kid != testHolderDID+"#key-1" {
		t.Fatalf("kid = %v, want %s", kid, testHolderDID+"#key-1")
	}
	if _, err := vp.ParsePresentation([]byte(result.Token), vp.WithResolver(f.resolver), vp.WithVerifyProof()); err != nil {
		t.Fatalf("issued presentation does not verify: %v", err)
	}
}

func TestVPBuilder_Build_SignerKeyMismatch(t *testing.T) {
	f := newVPFixture(t)
	_, otherBytes := newTestKey(t)

	result, err := newTestVPBuilder(WithVPBuilderResolver(f.resolver)).Build(context.Background(), f.data(),
		WithVPSignerOptions(signer.WithPrivateKey(otherBytes)))
	if err == nil || result != nil {
		t.Fatalf("Build() = (%v, %v), want error when signer key differs from the holder's VM", result, err)
	}
	for _, want := range []string{testHolderDID + "#key-1", "WithVerificationMethodKey"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestVPBuilder_Build_DefaultValidFromSetsIat(t *testing.T) {
	f := newVPFixture(t)

	result, err := newTestVPBuilder(WithVPBuilderResolver(f.resolver)).Build(context.Background(), f.data(),
		WithVPSignerOptions(signer.WithPrivateKey(f.holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	claims := jwtClaims(t, result.Token)
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("token has no iat claim: %v", claims)
	}
	if diff := math.Abs(float64(time.Now().Unix()) - iat); diff > 5 {
		t.Fatalf("iat %v is %vs away from now", iat, diff)
	}
}

func TestVPBuilder_Build_CallOptionOverridesBuilder(t *testing.T) {
	f := newVPFixture(t)

	b := newTestVPBuilder(WithVPBuilderResolver(verificationmethod.NewStaticResolver()))
	if _, err := b.Build(context.Background(), f.data(),
		WithVPSignerOptions(signer.WithPrivateKey(f.holderKeyBytes)), WithVPBuilderResolver(f.resolver)); err != nil {
		t.Fatalf("Build() with call-level resolver error = %v", err)
	}
}
