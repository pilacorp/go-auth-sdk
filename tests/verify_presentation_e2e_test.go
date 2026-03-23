package test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/auth/verifier"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func TestVerifyPresentationFlow(t *testing.T) {
	ctx := context.Background()

	issuerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))

	didServer := newLocalDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	policy1 := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Credential:Create")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)

	policy2 := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Credential:Update")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)

	credentialStatus := []vc.Status{
		{
			ID:                   "https://example.com/status/0#0",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		},
	}

	issuerSigner := ecdsa.NewPrivSigner(nil)
	vcBuilder := builder.NewAuthBuilder(
		builder.WithBuilderSchemaID("https://example.com/schema/v1"),
		builder.WithSigner(issuerSigner),
	)

	vcA, err := vcBuilder.Build(ctx, model.AuthData{
		IssuerDID:        issuerDID,
		HolderDID:        holderDID,
		Policy:           policy1,
		CredentialStatus: credentialStatus,
	}, builder.WithSignerOptions(signer.WithPrivateKey(issuerKeyBytes)))
	if err != nil {
		t.Fatalf("build vcA: %v", err)
	}

	vcB, err := vcBuilder.Build(ctx, model.AuthData{
		IssuerDID:        issuerDID,
		HolderDID:        holderDID,
		Policy:           policy2,
		CredentialStatus: credentialStatus,
	}, builder.WithSignerOptions(signer.WithPrivateKey(issuerKeyBytes)))
	if err != nil {
		t.Fatalf("build vcB: %v", err)
	}

	holderSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(holderSigner))

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcA.Token, vcB.Token},
		ValidFrom:  ptrTime(time.Now()),
		ValidUntil: ptrTime(time.Now().Add(5 * time.Minute)),
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp: %v", err)
	}

	result, err := verifier.VerifyPresentation(ctx, []byte(vpResp.Token),
		verifier.WithVPVerifyProof(),
		verifier.WithVPCheckExpiration(),
		verifier.WithVPDIDBaseURL(didBaseURL),
		verifier.WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("verify presentation: %v", err)
	}

	if result.HolderDID != holderDID {
		t.Fatalf("holder DID mismatch: got %q want %q", result.HolderDID, holderDID)
	}

	if len(result.VCs) != 2 {
		t.Fatalf("embedded VC count mismatch: got %d want 2", len(result.VCs))
	}

	// Verify each VC token separately (callers should verify each VC based on their business logic)
	actions := map[string]bool{}
	for i, vc := range result.VCs {
		vcResult, err := verifier.Verify(ctx, []byte(vc.Token),
			verifier.WithVerifyProof(),
			verifier.WithCheckExpiration(),
			verifier.WithVerifyPermissions(),
			verifier.WithDIDBaseURL(didBaseURL),
			verifier.WithVerificationMethodKey("key-1"),
		)
		if err != nil {
			t.Fatalf("verify embedded vc[%d]: %v", i, err)
		}
		for _, stmt := range vcResult.Permissions {
			for _, a := range stmt.Actions {
				actions[a.String()] = true
			}
		}
	}

	if !actions["Credential:Create"] {
		t.Fatalf("missing action Credential:Create in embedded VC permissions")
	}
	if !actions["Credential:Update"] {
		t.Fatalf("missing action Credential:Update in aggregated permissions")
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func newLocalDIDServer(t *testing.T, issuerDID, issuerPubHex, holderDID, holderPubHex string) *httptest.Server {
	t.Helper()

	buildDoc := func(did, pubHex string) map[string]any {
		vmID := did + "#key-1"
		return map[string]any{
			"@context": []string{"https://www.w3.org/ns/did/v1"},
			"id":       did,
			"verificationMethod": []map[string]any{
				{
					"id":           vmID,
					"type":         "EcdsaSecp256k1VerificationKey2019",
					"controller":   did,
					"publicKeyHex": "0x" + pubHex,
				},
			},
			"authentication":      []string{vmID},
			"assertionMethod":     []string{vmID},
			"didDocumentMetadata": map[string]any{},
		}
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/did/") {
			http.NotFound(w, r)
			return
		}

		didEncoded := strings.TrimPrefix(r.URL.Path, "/api/v1/did/")
		did, err := url.PathUnescape(didEncoded)
		if err != nil {
			http.Error(w, "invalid did", http.StatusBadRequest)
			return
		}

		var doc map[string]any
		switch did {
		case issuerDID:
			doc = buildDoc(issuerDID, issuerPubHex)
		case holderDID:
			doc = buildDoc(holderDID, holderPubHex)
		default:
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	return httptest.NewServer(h)
}
