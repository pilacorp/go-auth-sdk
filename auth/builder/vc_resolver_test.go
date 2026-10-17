package builder

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

const (
	testIssuerDID = "did:test:issuer"
	testHolderDID = "did:test:holder"
	testSchemaID  = "https://example.com/schema/v1"
)

func testVCData() model.VCData {
	return model.VCData{
		IssuerDID: testIssuerDID,
		HolderDID: testHolderDID,
		Policy: policy.NewPolicy(policy.WithStatements(policy.NewStatement(
			policy.EffectAllow,
			[]policy.Action{policy.NewAction("Credential:Create")},
			[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
			policy.NewCondition(),
		))),
		CredentialStatus: getDefaultTestStatus(),
	}
}

func newTestVCBuilder(opts ...VCBuilderConfigOption) *VCBuilder {
	base := []VCBuilderConfigOption{WithBuilderSchemaID(testSchemaID), WithSigner(ecdsa.NewPrivSigner(nil))}
	return NewVCBuilder(append(base, opts...)...)
}

func TestVCBuilder_Build_WithResolver(t *testing.T) {
	priv, privBytes := newTestKey(t)
	r := newTestResolver(t, map[string]*ecdsaPub{testIssuerDID: &priv.PublicKey})

	result, err := newTestVCBuilder(WithBuilderResolver(r)).Build(context.Background(), testVCData(),
		WithSignerOptions(signer.WithPrivateKey(privBytes)))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if kid := jwtHeader(t, result.Token)["kid"]; kid != testIssuerDID+"#key-1" {
		t.Fatalf("kid = %v, want %s", kid, testIssuerDID+"#key-1")
	}
	if _, err := vc.ParseCredential([]byte(result.Token), vc.WithResolver(r), vc.WithVerifyProof()); err != nil {
		t.Fatalf("issued token does not verify: %v", err)
	}
}

func TestVCBuilder_Build_SignerKeyMismatch(t *testing.T) {
	published, _ := newTestKey(t)
	_, otherBytes := newTestKey(t)
	r := newTestResolver(t, map[string]*ecdsaPub{testIssuerDID: &published.PublicKey})

	result, err := newTestVCBuilder(WithBuilderResolver(r)).Build(context.Background(), testVCData(),
		WithSignerOptions(signer.WithPrivateKey(otherBytes)))
	if err == nil {
		t.Fatalf("Build() expected error when signer key differs from the DID's VM, got token %v", result)
	}
	if result != nil {
		t.Fatalf("Build() returned a result alongside error: %+v", result)
	}
	for _, want := range []string{testIssuerDID + "#key-1", "WithVerificationMethodKey"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestVCBuilder_Build_UnknownDID(t *testing.T) {
	_, privBytes := newTestKey(t)

	result, err := newTestVCBuilder(WithBuilderResolver(verificationmethod.NewStaticResolver())).Build(
		context.Background(), testVCData(), WithSignerOptions(signer.WithPrivateKey(privBytes)))
	if err == nil || result != nil {
		t.Fatalf("Build() = (%v, %v), want error for unresolvable issuer DID", result, err)
	}
}

func TestVCBuilder_Build_DefaultValidFromSetsIat(t *testing.T) {
	priv, privBytes := newTestKey(t)
	r := newTestResolver(t, map[string]*ecdsaPub{testIssuerDID: &priv.PublicKey})

	result, err := newTestVCBuilder(WithBuilderResolver(r)).Build(context.Background(), testVCData(),
		WithSignerOptions(signer.WithPrivateKey(privBytes)))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	claims := jwtClaims(t, result.Token)
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("token has no iat claim: %v", claims)
	}
	if _, ok := claims["nbf"]; !ok {
		t.Fatalf("token has no nbf claim: %v", claims)
	}
	if diff := math.Abs(float64(time.Now().Unix()) - iat); diff > 5 {
		t.Fatalf("iat %v is %vs away from now", iat, diff)
	}
}

func TestVCBuilder_Build_CallOptionOverridesBuilder(t *testing.T) {
	priv, privBytes := newTestKey(t)
	good := newTestResolver(t, map[string]*ecdsaPub{testIssuerDID: &priv.PublicKey})

	b := newTestVCBuilder(WithBuilderResolver(verificationmethod.NewStaticResolver()))
	if _, err := b.Build(context.Background(), testVCData(),
		WithSignerOptions(signer.WithPrivateKey(privBytes)), WithBuilderResolver(good)); err != nil {
		t.Fatalf("Build() with call-level resolver error = %v", err)
	}
}

// Without WithBuilderBaseURL/WithBuilderResolver the builder must fall back to
// the SDK's package-level DID base URL (vc.Init), not an empty one.
func TestVCBuilder_Build_FallsBackToPackageBaseURL(t *testing.T) {
	priv, privBytes := newTestKey(t)
	doc := verificationmethod.NewDIDDocument(testIssuerDID,
		verificationmethod.NewSecp256k1VM(testIssuerDID, "key-1", pubHex(&priv.PublicKey)))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/"+testIssuerDID) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()

	vc.Init(srv.URL)
	t.Cleanup(func() { vc.Init(defaultDIDBaseURL) })

	if _, err := newTestVCBuilder().Build(context.Background(), testVCData(),
		WithSignerOptions(signer.WithPrivateKey(privBytes))); err != nil {
		t.Fatalf("Build() without base URL option error = %v", err)
	}
}
