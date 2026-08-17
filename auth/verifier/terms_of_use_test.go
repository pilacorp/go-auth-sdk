package verifier

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	ecdsasigner "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// buildTermsOfUseVC builds a signed VC-JWT, optionally carrying the
// presentation-required policy. The verification method key is pinned so the
// builder does not need to resolve a DID document.
func buildTermsOfUseVC(t *testing.T, requirePresentation bool) (token, issuerDID, holderDID string) {
	t.Helper()

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	issuerDID = "did:example:issuer"
	holderDID = "did:example:holder"

	testPolicy := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Credential:Create")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)

	b := builder.NewVCBuilder(
		builder.WithBuilderSchemaID("https://example.com/schema/v1"),
		builder.WithSigner(ecdsasigner.NewPrivSigner(nil)),
	)

	result, err := b.Build(context.Background(), model.VCData{
		IssuerDID: issuerDID,
		HolderDID: holderDID,
		Policy:    testPolicy,
		CredentialStatus: []vc.Status{{
			ID:                   "https://example.com/status/0#0",
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		}},
		RequirePresentation: requirePresentation,
	},
		builder.WithSignerOptions(signer.WithPrivateKey(crypto.FromECDSA(privateKey))),
		builder.WithVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}

	return result.Token, issuerDID, holderDID
}

// A credential carrying termsOfUse must still verify normally: the verifier does
// not model the property, and an unknown top-level field must not disturb
// issuer/holder/permission extraction.
func TestVCVerify_AcceptsCredentialCarryingTermsOfUse(t *testing.T) {
	ctx := context.Background()

	for _, requirePresentation := range []bool{false, true} {
		token, issuerDID, holderDID := buildTermsOfUseVC(t, requirePresentation)

		result, err := VCVerify(ctx, []byte(token))
		if err != nil {
			t.Fatalf("VCVerify(requirePresentation=%v) unexpected error: %v", requirePresentation, err)
		}

		if result.IssuerDID != issuerDID {
			t.Fatalf("IssuerDID = %q, want %q", result.IssuerDID, issuerDID)
		}
		if result.HolderDID != holderDID {
			t.Fatalf("HolderDID = %q, want %q", result.HolderDID, holderDID)
		}
		if len(result.Permissions) != 1 {
			t.Fatalf("Permissions length = %d, want 1", len(result.Permissions))
		}
	}
}

// The SDK deliberately does not enforce the policy. This pins that contract: if
// VCVerify ever starts rejecting bare presentation-required credentials, the
// README and this test have to change together.
func TestVCVerify_DoesNotEnforcePresentationRequired(t *testing.T) {
	ctx := context.Background()

	token, _, _ := buildTermsOfUseVC(t, true)

	if _, err := VCVerify(ctx, []byte(token)); err != nil {
		t.Fatalf("VCVerify() rejected a bare presentation-required credential: %v", err)
	}

	required, err := RequiresPresentation(token)
	if err != nil {
		t.Fatalf("RequiresPresentation() unexpected error: %v", err)
	}
	if !required {
		t.Fatal("the relying-party check failed to spot the presentation-required policy")
	}
}

// The relying-party check must distinguish the two credentials, and must survive
// a round trip through a presentation: VerifyPresentation hands back the raw VC
// tokens, and the policy has to still be readable on them.
func TestPresentationRequired_SurvivesPresentationRoundTrip(t *testing.T) {
	ctx := context.Background()

	plainToken, _, _ := buildTermsOfUseVC(t, false)
	if required, err := RequiresPresentation(plainToken); err != nil {
		t.Fatalf("RequiresPresentation() unexpected error: %v", err)
	} else if required {
		t.Fatal("a credential built without RequirePresentation must not carry the policy")
	}

	requiredToken, _, holderDID := buildTermsOfUseVC(t, true)

	holderKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate holder key: %v", err)
	}

	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsasigner.NewPrivSigner(nil)))
	vpResult, err := vpBuilder.Build(ctx, model.VPData{
		HolderDID: holderDID,
		VCTokens:  []string{requiredToken},
	},
		builder.WithVPSignerOptions(signer.WithPrivateKey(crypto.FromECDSA(holderKey))),
		builder.WithVPBuilderVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VPBuilder.Build() unexpected error: %v", err)
	}

	vpVerifyResult, err := VerifyPresentation(ctx, []byte(vpResult.Token))
	if err != nil {
		t.Fatalf("VerifyPresentation() unexpected error: %v", err)
	}

	if len(vpVerifyResult.VCs) != 1 {
		t.Fatalf("VCs length = %d, want 1", len(vpVerifyResult.VCs))
	}

	if required, err := RequiresPresentation(vpVerifyResult.VCs[0].Token); err != nil {
		t.Fatalf("RequiresPresentation() unexpected error: %v", err)
	} else if !required {
		t.Fatal("the policy was lost on the VC token extracted from the presentation")
	}

	if _, err := VCVerify(ctx, []byte(vpVerifyResult.VCs[0].Token)); err != nil {
		t.Fatalf("VCVerify() on the embedded credential unexpected error: %v", err)
	}
}

func TestRequiresPresentation(t *testing.T) {
	requiredToken, _, _ := buildTermsOfUseVC(t, true)
	plainToken, _, _ := buildTermsOfUseVC(t, false)

	tests := []struct {
		name    string
		token   string
		want    bool
		wantErr bool
	}{
		{name: "credential carrying the policy", token: requiredToken, want: true},
		{name: "credential without the policy", token: plainToken, want: false},
		{name: "empty token", token: "", wantErr: true},
		{name: "not a credential", token: "not-a-jwt", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RequiresPresentation(tt.token)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("RequiresPresentation() error = nil, want an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("RequiresPresentation() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("RequiresPresentation() = %v, want %v", got, tt.want)
			}
		})
	}
}
