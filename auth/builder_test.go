package auth

import (
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
)

func TestCredentialBuilder_Build(t *testing.T) {
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

	// Build credential with all options
	builder, err := NewCredentialBuilder(
		BuilderConfig{
			issuerDID: issuerDID,
			schemaID:  schemaID,
			signer:    ecdsaSigner,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create credential builder: %v", err)
	}

	result, err := builder.Build(ctx, CredentialData{
		holderDID:  holderDID,
		policy:     testPolicy,
		validFrom:  &validFrom,
		validUntil: &validUntil,
	}, signer.WithPrivateKey(privateKeyBytes))
	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Build() returned nil result")
	}
	if result.JWT == "" {
		t.Error("Build() JWT is empty")
	}
	t.Logf("Credential: %s", result.JWT)
}
