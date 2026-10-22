package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/signer"
	ecdsasigner "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

const (
	testAudience      = "did:test:verifier-a"
	testOtherAudience = "did:test:verifier-b"
	testNonce         = "nonce-1234"
)

// audienceNonceEnv builds VPs the way a client would and verifies them against
// a local DID server.
type audienceNonceEnv struct {
	didBaseURL string
	build      func(t *testing.T, audience, nonce string) string
}

func newAudienceNonceEnv(t *testing.T) *audienceNonceEnv {
	t.Helper()
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	holderPriv, _ := crypto.GenerateKey()
	issuerKey, holderKey := crypto.FromECDSA(issuerPriv), crypto.FromECDSA(holderPriv)
	issuerDID, holderDID := "did:test:issuer", "did:test:holder"

	didServer := newVPTestDIDServer(t, issuerDID, issuerKey, holderDID, holderKey)
	t.Cleanup(didServer.Close)
	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKey)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsasigner.NewPrivSigner(nil)))

	return &audienceNonceEnv{
		didBaseURL: didBaseURL,
		build: func(t *testing.T, audience, nonce string) string {
			t.Helper()
			resp, err := vpBuilder.Build(ctx, model.VPData{
				HolderDID: holderDID,
				VCTokens:  []string{vcToken},
				Audience:  audience,
				Nonce:     nonce,
			}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKey)))
			if err != nil {
				t.Fatalf("build vp: %v", err)
			}
			return resp.Token
		},
	}
}

func (e *audienceNonceEnv) verify(token string, opts ...VPVerifyOpt) (*model.VPVerifyResult, error) {
	base := []VPVerifyOpt{WithVPDIDBaseURL(e.didBaseURL)}
	return VerifyPresentation(context.Background(), []byte(token), append(base, opts...)...)
}

// jwtClaims decodes the payload of a compact JWT.
func jwtClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

// withClaim rewrites one payload claim and keeps the old signature, as an
// attacker would.
func withClaim(t *testing.T, token, name string, value interface{}) string {
	t.Helper()
	parts := strings.Split(token, ".")
	claims := jwtClaims(t, token)
	claims[name] = value
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]
}

func TestVPBuilder_SignsAudienceAndNonce(t *testing.T) {
	env := newAudienceNonceEnv(t)

	claims := jwtClaims(t, env.build(t, testAudience, testNonce))
	if claims["aud"] != testAudience {
		t.Errorf("aud = %v, want %q", claims["aud"], testAudience)
	}
	if claims["nonce"] != testNonce {
		t.Errorf("nonce = %v, want %q", claims["nonce"], testNonce)
	}

	// Without the fields the token carries neither claim, as before.
	claims = jwtClaims(t, env.build(t, "", ""))
	if _, ok := claims["aud"]; ok {
		t.Errorf("aud written although Audience is empty: %v", claims["aud"])
	}
	if _, ok := claims["nonce"]; ok {
		t.Errorf("nonce written although Nonce is empty: %v", claims["nonce"])
	}
}

func TestVerifyPresentation_ExpectedAudience(t *testing.T) {
	env := newAudienceNonceEnv(t)
	bound := env.build(t, testAudience, testNonce)
	unbound := env.build(t, "", "")

	cases := []struct {
		name    string
		token   string
		opts    []VPVerifyOpt
		wantErr string
	}{
		{name: "aud names this verifier", token: bound, opts: []VPVerifyOpt{WithVPExpectedAudience(testAudience)}},
		{name: "aud names another verifier", token: bound, opts: []VPVerifyOpt{WithVPExpectedAudience(testOtherAudience)}, wantErr: "aud"},
		{name: "no aud while one is expected", token: unbound, opts: []VPVerifyOpt{WithVPExpectedAudience(testAudience)}, wantErr: "aud"},
		{name: "aud rewritten after signing", token: withClaim(t, bound, "aud", testOtherAudience),
			opts: []VPVerifyOpt{WithVPExpectedAudience(testOtherAudience)}, wantErr: "failed to parse presentation"},
		{name: "empty expected audience is a configuration error", token: bound, opts: []VPVerifyOpt{WithVPExpectedAudience("")},
			wantErr: "expected audience must not be empty"},
		// Without the option nothing changes: an unbound VP and a bound one both verify.
		{name: "no option, unbound vp", token: unbound, opts: []VPVerifyOpt{WithVPVerifyProof()}},
		{name: "no option, bound vp", token: bound, opts: []VPVerifyOpt{WithVPVerifyProof()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := env.verify(tc.token, tc.opts...)
			assertLeewayErr(t, err, tc.wantErr)
		})
	}
}

func TestVerifyPresentation_ReturnsNonce(t *testing.T) {
	env := newAudienceNonceEnv(t)

	res, err := env.verify(env.build(t, testAudience, testNonce), WithVPVerifyProof(), WithVPExpectedAudience(testAudience))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Nonce != testNonce {
		t.Errorf("Nonce = %q, want %q", res.Nonce, testNonce)
	}

	res, err = env.verify(env.build(t, "", ""), WithVPVerifyProof())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Nonce != "" {
		t.Errorf("Nonce = %q for a VP without one, want empty", res.Nonce)
	}

	// A nonce changed after signing breaks the signature.
	_, err = env.verify(withClaim(t, env.build(t, "", testNonce), "nonce", "other-nonce"), WithVPVerifyProof())
	if err == nil {
		t.Fatal("a VP whose nonce was rewritten after signing was accepted")
	}
}

func TestVPVerifyOptions_ExpectedAudience(t *testing.T) {
	opts, err := getVPVerifyOptions(WithVPExpectedAudience(testAudience))
	if err != nil {
		t.Fatalf("getVPVerifyOptions: %v", err)
	}
	if opts.expectedAudience != testAudience {
		t.Errorf("expectedAudience = %q, want %q", opts.expectedAudience, testAudience)
	}

	if _, err := getVPVerifyOptions(WithVPExpectedAudience("")); err == nil {
		t.Error("WithVPExpectedAudience(\"\") was accepted, want a configuration error")
	}
}
