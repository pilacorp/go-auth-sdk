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

// getDefaultTestStatus returns a default status for testing purposes
func getDefaultTestStatus() []vc.Status {
	return []vc.Status{
		{
			ID:                   "https://example.com/status/0#0",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		},
	}
}

func TestAuthBuilder_Build(t *testing.T) {
	ctx := context.Background()

	// Generate a private key for testing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	// Create ECDSA provider
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

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
	builder := NewAuthBuilder(WithBuilderSchemaID(schemaID), WithSigner(ecdsaSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        issuerDID,
		HolderDID:        holderDID,
		Policy:           testPolicy,
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntil,
		CredentialStatus: expectedStatus,
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
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

func TestAuthBuilder_WithSigner_NilPreservesDefault(t *testing.T) {
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

	// Create builder with WithSigner(nil) - should preserve default signer
	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(nil))

	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with WithSigner(nil) should succeed (uses default signer): %v", err)
	}
	if result == nil {
		t.Fatal("Build() with WithSigner(nil) should return result")
	}
	if result.Token == "" {
		t.Error("Build() with WithSigner(nil) should return non-empty token")
	}
}

func TestAuthBuilder_Build_EmptyPolicy(t *testing.T) {
	ctx := context.Background()
	privateKey, _ := crypto.GenerateKey()
	privateKeyBytes := crypto.FromECDSA(privateKey)
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

	emptyPolicy := policy.NewPolicy()
	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(ecdsaSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder",
		Policy:           emptyPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

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
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

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

	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(ecdsaSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
		// ValidFrom and ValidUntil are nil
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

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
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

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

	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(ecdsaSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder",
		Policy:           testPolicy,
		ValidFrom:        &validFrom,
		CredentialStatus: getDefaultTestStatus(),
		// ValidUntil is nil
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

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
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

	// Build multiple credentials with same builder
	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(ecdsaSigner))
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

		result, err := builder.Build(ctx, AuthData{
			IssuerDID:        "did:example:issuer",
			HolderDID:        holderDID,
			Policy:           testPolicy,
			CredentialStatus: getDefaultTestStatus(),
		}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

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
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

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
	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(ecdsaSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSignerOptions(signer.WithPrivateKey(invalidKey)))

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
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

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

	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(ecdsaSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "", // Empty holder DID
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

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
	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(vaultSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder",
		Policy:           testPolicy,
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntil,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSignerOptions(signer.WithSignerAddress(signerAddress)))

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
	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(vaultSigner))
	result, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	} /* no signer address option */)

	// Should fail because signer address is required for Vault
	if err == nil {
		t.Error("Build() should return error when signer address is missing for Vault signer")
	}
	if result != nil {
		t.Error("Build() should return nil result when signing fails")
	}
}

func TestAuthBuilder_Build_OverrideSigner(t *testing.T) {
	ctx := context.Background()

	// Generate two different private keys
	privateKey1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key 1: %v", err)
	}
	privateKeyBytes1 := crypto.FromECDSA(privateKey1)

	privateKey2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key 2: %v", err)
	}
	privateKeyBytes2 := crypto.FromECDSA(privateKey2)

	// Create two different signers
	signer1 := ecdsa.NewPrivSigner(privateKeyBytes1)
	signer2 := ecdsa.NewPrivSigner(privateKeyBytes2)

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

	// Create builder with signer1
	builder := NewAuthBuilder(WithBuilderSchemaID("https://example.com/schema/v1"), WithSigner(signer1))

	// Build with signer1 (default from builder)
	result1, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder1",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	})
	if err != nil {
		t.Fatalf("Build() with default signer should succeed: %v", err)
	}
	if result1 == nil {
		t.Fatal("Build() should return result with default signer")
	}

	// Build with signer2 (override in Build call)
	result2, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder2",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSigner(signer2), WithSignerOptions(signer.WithPrivateKey(privateKeyBytes2)))
	if err != nil {
		t.Fatalf("Build() with overridden signer should succeed: %v", err)
	}
	if result2 == nil {
		t.Fatal("Build() should return result with overridden signer")
	}

	// Verify that builder's original signer is not changed (immutability)
	// Build again without override should still use signer1
	result3, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder3",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	})
	if err != nil {
		t.Fatalf("Build() with original signer should still work: %v", err)
	}
	if result3 == nil {
		t.Fatal("Build() should return result with original signer")
	}

	// Verify tokens are different (different signers produce different signatures)
	if result1.Token == result2.Token {
		t.Error("Tokens should be different when using different signers")
	}
	if result1.Token == result3.Token {
		t.Error("Tokens should be different for different holders")
	}
}

func TestAuthBuilder_Build_OverrideSchemaID(t *testing.T) {
	ctx := context.Background()

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

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

	// Create builder with schemaID1
	schemaID1 := "https://example.com/schema/v1"
	schemaID2 := "https://example.com/schema/v2"
	builder := NewAuthBuilder(WithBuilderSchemaID(schemaID1), WithSigner(ecdsaSigner))

	// Build with schemaID1 (default from builder)
	result1, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder1",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with default schemaID should succeed: %v", err)
	}
	if result1 == nil {
		t.Fatal("Build() should return result with default schemaID")
	}

	// Build with schemaID2 (override in Build call)
	result2, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder2",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithBuilderSchemaID(schemaID2), WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with overridden schemaID should succeed: %v", err)
	}
	if result2 == nil {
		t.Fatal("Build() should return result with overridden schemaID")
	}

	// Verify that builder's original schemaID is not changed (immutability)
	// Build again without override should still use schemaID1
	result3, err := builder.Build(ctx, AuthData{
		IssuerDID:        "did:example:issuer",
		HolderDID:        "did:example:holder3",
		Policy:           testPolicy,
		CredentialStatus: getDefaultTestStatus(),
	}, WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with original schemaID should still work: %v", err)
	}
	if result3 == nil {
		t.Fatal("Build() should return result with original schemaID")
	}

	// Verify tokens are different (different schemaIDs produce different credentials)
	if result1.Token == result2.Token {
		t.Error("Tokens should be different when using different schemaIDs")
	}
	if result1.Token == result3.Token {
		t.Error("Tokens should be different for different holders")
	}
}
