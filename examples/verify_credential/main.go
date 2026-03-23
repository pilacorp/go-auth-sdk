package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/auth/verifier"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
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
	ecdsaSigner := ecdsa.NewPrivSigner(nil)

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&privateKey.PublicKey))
	staticResolver, err := verificationmethod.NewStaticResolver(issuerPubHex)
	if err != nil {
		log.Fatalf("Failed to create static resolver: %v", err)
	}

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

	// Step 4: Create credential status (required)
	credentialStatus := []vc.Status{
		{
			ID:                   "https://example.com/status/0#0",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		},
	}

	// Step 5: Create AuthBuilder and build credential
	issuerDID := "did:example:issuer"
	schemaID := "https://example.com/schema/v1"
	validFrom := time.Now()
	validUntil := time.Now().Add(24 * time.Hour)

	authBuilder := builder.NewVCBuilder(builder.WithVCBuilderSchemaID(schemaID), builder.WithVCSigner(ecdsaSigner))
	result, err := authBuilder.Build(ctx, model.VCData{
		IssuerDID:        issuerDID,
		HolderDID:        "did:example:holder",
		Policy:           policy,
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntil,
		CredentialStatus: credentialStatus,
	}, builder.WithVCSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
	if err != nil {
		log.Fatalf("Failed to build credential: %v", err)
	}

	fmt.Println("✓ Credential created successfully")
	fmt.Printf("Token: %s\n\n", result.Token)

	// Step 6: Verify credential
	fmt.Println("Verifying credential...")
	verifyResult, err := verifier.VerifyCredential(
		ctx,
		[]byte(result.Token),
		verifier.WithVerifyProof(),
		verifier.WithCheckExpiration(),
		verifier.WithResolver(staticResolver),
		verifier.WithVerifyPermissions(),
	)
	if err != nil {
		log.Fatalf("Credential verification failed: %v", err)
	}

	fmt.Println("✓ Credential verified successfully")
	fmt.Printf("Issuer DID: %s\n", verifyResult.IssuerDID)
	fmt.Printf("Holder DID: %s\n", verifyResult.HolderDID)
	fmt.Printf("Permissions: %d\n", len(verifyResult.Permissions))
}
