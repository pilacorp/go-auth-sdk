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
)

func main() {
	ctx := context.Background()

	fmt.Print("=== Create and Verify Credential ===\n\n")

	// Step 1: Generate a private key for signing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)

	// Step 2: Create signer
	ecdsaSigner := ecdsa.NewPrivSigner()

	// Step 3: Create policy
	policy := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Credential:Create")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)

	// Step 4: Create AuthBuilder
	builder, err := auth.NewAuthBuilder(
		"did:example:issuer",
		"https://example.com/schema/v1",
		ecdsaSigner,
	)
	if err != nil {
		log.Fatalf("Failed to create AuthBuilder: %v", err)
	}

	// Step 5: Build credential
	validFrom := time.Now()
	validUntil := time.Now().Add(24 * time.Hour)
	result, err := builder.Build(ctx, auth.AuthData{
		HolderDID:  "did:example:holder",
		Policy:     policy,
		ValidFrom:  &validFrom,
		ValidUntil: &validUntil,
	}, signer.WithPrivateKey(privateKeyBytes))
	if err != nil {
		log.Fatalf("Failed to build credential: %v", err)
	}

	fmt.Println("✓ Credential created successfully")
	fmt.Printf("Token: %s\n\n", result.Token)

	// Step 6: Verify credential
	fmt.Println("Verifying credential...")
	verifyResult, err := auth.Verify(
		ctx,
		[]byte(result.Token),
		auth.WithVerifyProof(),
		auth.WithCheckExpiration(),
		auth.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
		auth.WithVerificationMethodKey("key-1"),
		auth.WithVerifyPermissions(),
	)
	if err != nil {
		log.Fatalf("Credential verification failed: %v", err)
	}

	fmt.Println("✓ Credential verified successfully")
	fmt.Printf("Issuer DID: %s\n", verifyResult.IssuerDID)
	fmt.Printf("Holder DID: %s\n", verifyResult.HolderDID)
	fmt.Printf("Permissions: %d\n", len(verifyResult.Permissions))
}
