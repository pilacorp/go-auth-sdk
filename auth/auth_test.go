package auth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-auth-sdk/signer/vault"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

func TestAuthBuilder_Build(t *testing.T) {
	ctx := context.Background()

	// Generate a private key for testing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	// Create ECDSA provider
	ecdsaSigner := ecdsa.NewPrivSigner()

	// Create comprehensive policy with multiple statements and conditions
	actions1 := []policy.Action{
		policy.NewAction("Credential:Create"),
		policy.NewAction("Credential:Update"),
	}
	resources1 := []policy.Resource{
		policy.NewResource(policy.ResourceObjectCredential),
		policy.NewResource(policy.ResourceObjectIssuer),
	}
	conditions1 := policy.NewCondition()
	conditions1.Add("StringEquals", "tenant", "test-tenant")

	actions2 := []policy.Action{policy.NewAction("Credential:Delete")}
	resources2 := []policy.Resource{policy.NewResource(policy.ResourceObjectCredential)}
	conditions2 := policy.NewCondition()

	testPolicy := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(policy.EffectAllow, actions1, resources1, conditions1),
			policy.NewStatement(policy.EffectDeny, actions2, resources2, conditions2),
		),
	)

	validFrom := time.Now()
	validUntil := time.Now().Add(24 * time.Hour)
	schemaID := "https://example.com/schema/v1"
	issuerDID := "did:example:issuer"
	holderDID := "did:example:holder"

	statusListCred := "https://example.com/status/1"
	expectedStatus := []vc.Status{
		{
			ID:                   "https://example.com/status/1#1",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "1",
			StatusListCredential: statusListCred,
		},
	}

	// Build credential with all options
	result, err := Build(ctx, AuthData{
		IssuerDID:        issuerDID,
		SchemaID:         schemaID,
		HolderDID:        holderDID,
		Policy:           testPolicy,
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntil,
		CredentialStatus: expectedStatus,
	}, ecdsaSigner, signer.WithPrivateKey(privateKeyBytes))
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Build() returned nil result")
	}
	if result.Token == "" {
		t.Error("Build() JWT is empty")
	}
	t.Logf("Credential: %s", result.Token)
}

func TestBuild_DefaultSchemaID_WhenEmpty(t *testing.T) {
	ctx := context.Background()

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)

	ecdsaSigner := ecdsa.NewPrivSigner()

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

	// SchemaID left empty to trigger default
	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		HolderDID: "did:example:holder",
		Policy:    testPolicy,
	}, ecdsaSigner, signer.WithPrivateKey(privateKeyBytes))
	if err != nil {
		t.Fatalf("Build() with empty SchemaID should succeed and use default: %v", err)
	}
	if result == nil {
		t.Fatal("Build() should return result when using default SchemaID")
	}

	// Verify the credential using the Verify function with expected schema ID.
	// This ensures that:
	//   - The credential can be parsed correctly
	//   - The embedded schema ID equals DefaultSchemaID
	if _, err := Verify(ctx, []byte(result.Token), WithSchemaID(DefaultSchemaID)); err != nil {
		t.Fatalf("expected credential to use default schema ID %q, but verification failed: %v", DefaultSchemaID, err)
	}
}

func TestBuild_NilSigner_UsesDefaultECDSA(t *testing.T) {
	ctx := context.Background()
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)

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

	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		SchemaID:  "https://example.com/schema/v1",
		HolderDID: "did:example:holder",
		Policy:    testPolicy,
	}, nil, signer.WithPrivateKey(privateKeyBytes))
	if err != nil {
		t.Fatalf("Build() with nil signer should succeed: %v", err)
	}
	if result == nil {
		t.Fatal("Build() with nil signer should return result")
	}
	if result.Token == "" {
		t.Error("Build() with nil signer should return non-empty token")
	}
}

func TestAuthBuilder_Build_EmptyPolicy(t *testing.T) {
	ctx := context.Background()
	privateKey, _ := crypto.GenerateKey()
	privateKeyBytes := crypto.FromECDSA(privateKey)
	ecdsaSigner := ecdsa.NewPrivSigner()

	emptyPolicy := policy.NewPolicy()
	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		SchemaID:  "https://example.com/schema/v1",
		HolderDID: "did:example:holder",
		Policy:    emptyPolicy,
	}, ecdsaSigner, signer.WithPrivateKey(privateKeyBytes))

	if err != nil {
		t.Fatalf("Build() with empty policy should succeed: %v", err)
	}
	if result == nil {
		t.Fatal("Build() should return result even with empty policy")
	}
	if result.Token == "" {
		t.Error("Build() should return non-empty token even with empty policy")
	}
}

func TestAuthBuilder_Build_WithoutValidityPeriod(t *testing.T) {
	ctx := context.Background()
	privateKey, _ := crypto.GenerateKey()
	privateKeyBytes := crypto.FromECDSA(privateKey)
	ecdsaSigner := ecdsa.NewPrivSigner()

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

	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		SchemaID:  "https://example.com/schema/v1",
		HolderDID: "did:example:holder",
		Policy:    testPolicy,
		// ValidFrom and ValidUntil are nil
	}, ecdsaSigner, signer.WithPrivateKey(privateKeyBytes))

	if err != nil {
		t.Fatalf("Build() without validity period should succeed: %v", err)
	}
	if result == nil {
		t.Fatal("Build() should return result even without validity period")
	}
	if result.Token == "" {
		t.Error("Build() should return non-empty token even without validity period")
	}
}

func TestAuthBuilder_Build_OnlyValidFrom(t *testing.T) {
	ctx := context.Background()
	privateKey, _ := crypto.GenerateKey()
	privateKeyBytes := crypto.FromECDSA(privateKey)
	ecdsaSigner := ecdsa.NewPrivSigner()

	validFrom := time.Now()
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

	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		SchemaID:  "https://example.com/schema/v1",
		HolderDID: "did:example:holder",
		Policy:    testPolicy,
		ValidFrom: &validFrom,
		// ValidUntil is nil
	}, ecdsaSigner, signer.WithPrivateKey(privateKeyBytes))

	if err != nil {
		t.Fatalf("Build() with only ValidFrom should succeed: %v", err)
	}
	if result == nil {
		t.Fatal("Build() should return result with only ValidFrom")
	}
}

func TestAuthBuilder_Build_MultipleCredentials(t *testing.T) {
	ctx := context.Background()
	privateKey, _ := crypto.GenerateKey()
	privateKeyBytes := crypto.FromECDSA(privateKey)
	ecdsaSigner := ecdsa.NewPrivSigner()

	// Build multiple credentials with same builder
	holders := []string{"did:example:holder1", "did:example:holder2", "did:example:holder3"}
	for i, holderDID := range holders {
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

		result, err := Build(ctx, AuthData{
			IssuerDID: "did:example:issuer",
			SchemaID:  "https://example.com/schema/v1",
			HolderDID: holderDID,
			Policy:    testPolicy,
		}, ecdsaSigner, signer.WithPrivateKey(privateKeyBytes))

		if err != nil {
			t.Fatalf("Build() #%d failed: %v", i+1, err)
		}
		if result == nil {
			t.Fatalf("Build() #%d returned nil result", i+1)
		}
		if result.Token == "" {
			t.Errorf("Build() #%d returned empty token", i+1)
		}
	}
}

func TestAuthBuilder_Build_InvalidPrivateKey(t *testing.T) {
	ctx := context.Background()
	ecdsaSigner := ecdsa.NewPrivSigner()

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

	// Use invalid private key (too short)
	invalidKey := []byte{1, 2, 3}
	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		SchemaID:  "https://example.com/schema/v1",
		HolderDID: "did:example:holder",
		Policy:    testPolicy,
	}, ecdsaSigner, signer.WithPrivateKey(invalidKey))

	// Should fail because invalid private key
	if err == nil {
		t.Error("Build() should return error with invalid private key")
	}
	if result != nil {
		t.Error("Build() should return nil result when signing fails")
	}
}

func TestAuthBuilder_Build_EmptyHolderDID(t *testing.T) {
	ctx := context.Background()
	privateKey, _ := crypto.GenerateKey()
	privateKeyBytes := crypto.FromECDSA(privateKey)
	ecdsaSigner := ecdsa.NewPrivSigner()

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

	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		SchemaID:  "https://example.com/schema/v1",
		HolderDID: "", // Empty holder DID
		Policy:    testPolicy,
	}, ecdsaSigner, signer.WithPrivateKey(privateKeyBytes))

	// Empty holder DID should return error
	if err == nil {
		t.Error("Build() should return error for empty holder DID")
	}
	if err.Error() != "holder DID is required" {
		t.Errorf("Build() error = %v, want 'holder DID is required'", err)
	}
	if result != nil {
		t.Error("Build() should return nil result when holder DID is empty")
	}
}

func TestAuthBuilder_Build_WithVaultSigner(t *testing.T) {
	ctx := context.Background()

	// Create test policy
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

	// Generate a mock signature (64 bytes)
	mockSignature := make([]byte, 64)
	for i := range mockSignature {
		mockSignature[i] = byte(i % 256)
	}

	signerAddress := "0x1234567890123456789012345678901234567890"

	// Create mock Vault server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request path contains the address
		expectedPath := "/v1/secp/accounts/" + signerAddress + "/signRaw"
		if r.URL.Path != expectedPath {
			t.Errorf("Path = %v, want %v", r.URL.Path, expectedPath)
		}

		// Verify Authorization header
		if r.Header.Get("X-Vault-Token") != "test-vault-token" {
			t.Errorf("X-Vault-Token = %v, want 'test-vault-token'", r.Header.Get("X-Vault-Token"))
		}

		// Verify request body
		var req struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}

		// Create response
		response := struct {
			Data struct {
				Signed string `json:"signature"`
			} `json:"data"`
		}{
			Data: struct {
				Signed string `json:"signature"`
			}{
				Signed: "0x" + hex.EncodeToString(mockSignature),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create Vault signer
	vaultSigner := vault.NewVaultSigner(server.URL, "test-vault-token")

	validFrom := time.Now()
	validUntil := time.Now().Add(24 * time.Hour)

	// Build credential with Vault signer
	result, err := Build(ctx, AuthData{
		IssuerDID:  "did:example:issuer",
		SchemaID:   "https://example.com/schema/v1",
		HolderDID:  "did:example:holder",
		Policy:     testPolicy,
		ValidFrom:  &validFrom,
		ValidUntil: &validUntil,
	}, vaultSigner, signer.WithSignerAddress(signerAddress))

	if err != nil {
		t.Fatalf("Build() with Vault signer unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Build() should return result with Vault signer")
	}
	if result.Token == "" {
		t.Error("Build() should return non-empty token with Vault signer")
	}
	t.Logf("Credential with Vault signer: %s", result.Token)
}

func TestAuthBuilder_Build_WithVaultSigner_MissingAddress(t *testing.T) {
	ctx := context.Background()

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

	// Create mock Vault server that should not be called
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Server should not be called without signer address")
	}))
	defer server.Close()

	vaultSigner := vault.NewVaultSigner(server.URL, "test-vault-token")

	// Build without signer address - should fail
	result, err := Build(ctx, AuthData{
		IssuerDID: "did:example:issuer",
		SchemaID:  "https://example.com/schema/v1",
		HolderDID: "did:example:holder",
		Policy:    testPolicy,
	}, vaultSigner /* no signer address option */)

	// Should fail because signer address is required for Vault
	if err == nil {
		t.Error("Build() should return error when signer address is missing for Vault signer")
	}
	if result != nil {
		t.Error("Build() should return nil result when signing fails")
	}
}

// Note: MergeDefaults behavior was part of the old AuthBuilder API and is no longer applicable
// with the simplified Build function that takes full AuthData per call.
