package verifier

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	ecdsasigner "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// leewayCase is one clock-skew scenario: the token is stamped validFrom =
// now + ahead, then verified with the given leeway.
type leewayCase struct {
	name    string
	ahead   time.Duration
	leeway  time.Duration
	wantErr string
}

var leewayCases = []leewayCase{
	{name: "signer clock ahead, no leeway", ahead: 5 * time.Second, wantErr: "not valid"},
	{name: "signer clock ahead, within leeway", ahead: 5 * time.Second, leeway: 30 * time.Second},
	{name: "signer clock ahead, beyond leeway", ahead: time.Minute, leeway: 30 * time.Second, wantErr: "not valid"},
	{name: "negative leeway counts as zero", ahead: 5 * time.Second, leeway: -time.Hour, wantErr: "not valid"},
}

// The VP builder stamps validFrom (and nbf) with the holder's clock. A holder
// whose clock runs ahead of the verifier's is refused on first use unless the
// verifier allows some leeway (go-credential-sdk #107).
func TestVerifyPresentation_WithVPLeeway(t *testing.T) {
	ctx := context.Background()
	issuerPriv, _ := crypto.GenerateKey()
	holderPriv, _ := crypto.GenerateKey()
	issuerKey, holderKey := crypto.FromECDSA(issuerPriv), crypto.FromECDSA(holderPriv)
	issuerDID, holderDID := "did:test:issuer", "did:test:holder"

	didServer := newVPTestDIDServer(t, issuerDID, issuerKey, holderDID, holderKey)
	defer didServer.Close()
	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKey)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsasigner.NewPrivSigner(nil)))

	for _, tc := range leewayCases {
		t.Run(tc.name, func(t *testing.T) {
			validFrom := time.Now().Add(tc.ahead)
			vpResp, err := vpBuilder.Build(ctx, model.VPData{
				HolderDID: holderDID,
				VCTokens:  []string{vcToken},
				ValidFrom: &validFrom,
			}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKey)))
			if err != nil {
				t.Fatalf("build vp: %v", err)
			}

			_, err = VerifyPresentation(ctx, []byte(vpResp.Token),
				WithVPVerifyProof(),
				WithVPCheckExpiration(),
				WithVPDIDBaseURL(didBaseURL),
				WithVPLeeway(tc.leeway),
			)
			assertLeewayErr(t, err, tc.wantErr)
		})
	}
}

// Same skew on the issuer side: the VC builder stamps validFrom with the
// issuer's clock.
func TestVCVerify_WithLeeway(t *testing.T) {
	ctx := context.Background()
	issuerPriv, _ := crypto.GenerateKey()
	holderPriv, _ := crypto.GenerateKey()
	issuerKey, holderKey := crypto.FromECDSA(issuerPriv), crypto.FromECDSA(holderPriv)
	issuerDID, holderDID := "did:test:issuer", "did:test:holder"

	didServer := newVPTestDIDServer(t, issuerDID, issuerKey, holderDID, holderKey)
	defer didServer.Close()
	didBaseURL := didServer.URL + "/api/v1/did"
	vc.Init(didBaseURL)

	vcBuilder := builder.NewVCBuilder(
		builder.WithBuilderSchemaID("https://example.com/schema/v1"),
		builder.WithSigner(ecdsasigner.NewPrivSigner(nil)),
	)

	for _, tc := range leewayCases {
		t.Run(tc.name, func(t *testing.T) {
			validFrom := time.Now().Add(tc.ahead)
			vcResp, err := vcBuilder.Build(ctx, model.VCData{
				IssuerDID: issuerDID,
				HolderDID: holderDID,
				ValidFrom: &validFrom,
				CredentialStatus: []vc.Status{{
					ID:                   "https://example.com/status/0#0",
					Type:                 "StatusList2021Entry",
					StatusPurpose:        "revocation",
					StatusListIndex:      "0",
					StatusListCredential: "https://example.com/status/0",
				}},
				Policy: policy.NewPolicy(policy.WithStatements(policy.NewStatement(
					policy.EffectAllow,
					[]policy.Action{policy.NewAction("Issuer:Create")},
					[]policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
					policy.NewCondition(),
				))),
			}, builder.WithSignerOptions(signer.WithPrivateKey(issuerKey)))
			if err != nil {
				t.Fatalf("build vc: %v", err)
			}

			_, err = VCVerify(ctx, []byte(vcResp.Token),
				WithVerifyProof(),
				WithCheckExpiration(),
				WithDIDBaseURL(didBaseURL),
				WithLeeway(tc.leeway),
			)
			assertLeewayErr(t, err, tc.wantErr)
		})
	}
}

func TestLeewayOptions_PassThrough(t *testing.T) {
	vcOpts, err := getVerifyOptions(WithLeeway(10 * time.Second))
	if err != nil {
		t.Fatalf("getVerifyOptions: %v", err)
	}
	if vcOpts.leeway != 10*time.Second {
		t.Errorf("WithLeeway: leeway = %v, want 10s", vcOpts.leeway)
	}

	vpOpts, err := getVPVerifyOptions(WithVPLeeway(10 * time.Second))
	if err != nil {
		t.Fatalf("getVPVerifyOptions: %v", err)
	}
	if vpOpts.leeway != 10*time.Second {
		t.Errorf("WithVPLeeway: leeway = %v, want 10s", vpOpts.leeway)
	}

	// Unset leeway adds no option, so the credential SDK keeps its exact default.
	if n, m := len(buildVPOptions(&vpVerifyOptions{})), len(buildVPOptions(&vpVerifyOptions{leeway: time.Second})); m != n+1 {
		t.Errorf("buildVPOptions: %d options with leeway, %d without; want one more", m, n)
	}
}

func assertLeewayErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want one mentioning %q", err, want)
	}
}
