package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

func main() {
	ctx := context.Background()

	fmt.Print("=== Building Verifiable Credential ===\n\n")

	// Step 1: Generate a private key for signing
	// In production, you would load this from secure storage
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println("✓ Generated private key")

	// Step 2: Create an ECDSA signer
	ecdsaSigner := ecdsa.NewPrivSigner(nil)
	fmt.Println("✓ Created ECDSA signer")

	// Step 3: Create a policy with permission statements
	// Define actions and resources for the first statement (Allow)
	actions1 := []policy.Action{
		policy.NewAction("Credential:Create"),
		policy.NewAction("Credential:Update"),
	}
	resources1 := []policy.Resource{
		policy.NewResource(policy.ResourceObjectCredential),
		policy.NewResource(policy.ResourceObjectIssuer),
	}
	conditions1 := policy.NewCondition()
	conditions1.Add("StringEquals", "tenant", "example-tenant")

	// Define actions and resources for the second statement (Deny)
	actions2 := []policy.Action{policy.NewAction("Credential:Delete")}
	resources2 := []policy.Resource{policy.NewResource(policy.ResourceObjectCredential)}
	conditions2 := policy.NewCondition()

	// Create policy with multiple statements
	testPolicy := policy.NewPolicy(
		policy.WithStatements(
			// Allow statement: can create and update credentials
			policy.NewStatement(policy.EffectAllow, actions1, resources1, conditions1),
			// Deny statement: cannot delete credentials
			policy.NewStatement(policy.EffectDeny, actions2, resources2, conditions2),
		),
	)
	fmt.Printf("✓ Created policy with %d statements\n", len(testPolicy.Permissions))

	// Step 4: Set validity period (optional)
	validFrom := time.Now()
	validUntil := time.Now().Add(24 * time.Hour)
	fmt.Println("✓ Set validity period")

	// Step 5: Prepare issuer and schema information
	issuerDID := "did:example:issuer"
	schemaID := "https://example.com/schema/v1"
	fmt.Printf("✓ Using IssuerDID: %s, SchemaID: %s\n", issuerDID, schemaID)

	// Step 6: Create credential status (required)
	credentialStatus := []vc.Status{
		{
			ID:                   "https://example.com/status/0#0",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		},
	}
	fmt.Println("✓ Created credential status")

	// Step 7: Create AuthBuilder
	builder := auth.NewAuthBuilder(schemaID, auth.WithSigner(ecdsaSigner))
	fmt.Println("✓ Created AuthBuilder")

	// Step 8: Build the credential
	holderDID := "did:example:holder"
	result, err := builder.Build(ctx, auth.AuthData{
		IssuerDID:        issuerDID,
		HolderDID:        holderDID,
		Policy:           testPolicy,
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntil,
		CredentialStatus: credentialStatus,
	}, auth.WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
	if err != nil {
		log.Fatalf("Failed to build credential: %v", err)
	}

	// Step 9: Use the credential token
	fmt.Println("\n=== Credential Built Successfully ===")
	fmt.Printf("Holder DID: %s\n", holderDID)
	fmt.Printf("Credential Token: %s\n", result.Token)
}
