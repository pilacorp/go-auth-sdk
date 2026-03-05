package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// TestBuildAndVerify simulates a full end-to-end flow:
// 1. Build a credential with AuthBuilder
// 2. Verify the resulting credential with Verify
func TestBuildAndVerify(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Mock DID resolver base URL to avoid hitting real network services.
	didServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For this E2E test we don't enable proof verification against DID,
		// so the exact payload is not important. We just return 200 OK.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer didServer.Close()

	// Generate a private key
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	privKeyBytes := crypto.FromECDSA(privKey)

	// Create policy
	stmt := policy.NewStatement(
		policy.EffectAllow,
		[]policy.Action{policy.NewAction("Credential:Create")},
		[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
		policy.NewCondition(),
	)
	p := policy.NewPolicy(policy.WithStatements(stmt))

	// Simple in-memory status (no real HTTP/status service)
	statuses := []vc.Status{
		{
			ID:                   "https://example.com/status/0#0",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		},
	}

	// Create signer and builder
	ecdsaSigner := ecdsa.NewPrivSigner(nil)
	builder := auth.NewAuthBuilder(
		auth.WithBuilderSchemaID("https://example.com/schema/v1"),
		auth.WithSigner(ecdsaSigner),
	)

	validFrom := time.Now()
	validUntil := time.Now().Add(5 * time.Minute)

	buildResult, err := builder.Build(ctx, auth.AuthData{
		IssuerDID:        "did:e2e:issuer",
		HolderDID:        "did:e2e:holder",
		Policy:           p,
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntil,
		CredentialStatus: statuses,
	}, auth.WithSignerOptions(signer.WithPrivateKey(privKeyBytes)))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if buildResult.Token == "" {
		t.Fatalf("Build() returned empty token")
	}

	// For E2E we call Verify, but keep it simple and fully offline:
	// - Use a mocked DID base URL to avoid real network calls.
	// - Only enable expiration check; proof verification uses external DID resolution.
	verifyResult, err := auth.Verify(
		ctx,
		[]byte(buildResult.Token),
		auth.WithDIDBaseURL(didServer.URL),
		auth.WithCheckExpiration(),
	)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if verifyResult.IssuerDID != "did:e2e:issuer" {
		t.Fatalf("unexpected IssuerDID: got %q, want %q", verifyResult.IssuerDID, "did:e2e:issuer")
	}
	if verifyResult.HolderDID != "did:e2e:holder" {
		t.Fatalf("unexpected HolderDID: got %q, want %q", verifyResult.HolderDID, "did:e2e:holder")
	}
	if len(verifyResult.Permissions) == 0 {
		t.Fatalf("expected non-empty permissions in verify result")
	}
}
