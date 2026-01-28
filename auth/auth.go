// Package auth provides the main API for building JWT Authorization Credentials (VC-JWT) with embedded permission policies.
// It supports both local private key and Vault signers.
// The package provides:
//   - AuthBuilder: A builder for creating and signing VC-JWT credentials with embedded permissions
//   - Verify: A function for verifying VC-JWT credentials and extracting permissions
//   - Verification options: Configurable options for proof verification, expiration checks, etc.

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// Build creates the VC-JWT payload and optionally signs it if a signer is available.
func Build(ctx context.Context, data AuthData, signer signer.Signer, opts ...signer.SignOption) (*AuthResponse, error) {
	// If signer is not provided, use ECDSA signer
	if signer == nil {
		signer = ecdsa.NewPrivSigner()
	}

	if err := validateAuthData(data); err != nil {
		return nil, err
	}
	// Build credential subject with permissions
	// vc.Subject has ID and CustomFields
	customFields := make(map[string]any)
	customFields["permissions"] = data.Policy.Permissions
	subject := vc.Subject{
		ID:           data.HolderDID,
		CustomFields: customFields,
	}

	// Build credential contents
	subjects := []vc.Subject{subject}
	if data.ID == "" {
		data.ID = uuid.NewString()
	}

	vcContents := vc.CredentialContents{
		Context: []any{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		ID: data.ID,
		Schemas: []vc.Schema{
			{
				ID:   data.SchemaID,
				Type: "JsonSchema",
			},
		},
		Issuer:           data.IssuerDID,
		Types:            []string{"VerifiableCredential", "AuthorizationCredential"},
		Subject:          subjects,
		CredentialStatus: data.CredentialStatus,
	}

	// Add validity period if provided
	if data.ValidFrom != nil {
		vcContents.ValidFrom = *data.ValidFrom
	}
	if data.ValidUntil != nil {
		vcContents.ValidUntil = *data.ValidUntil
	}

	// Create JWT credential
	vcCredential, err := vc.NewJWTCredential(vcContents)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT credential: %w", err)
	}

	// Sign the credential
	// Get signing input
	signData, err := vcCredential.GetSigningInput()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing input: %w", err)
	}

	// Hash the signing data
	hash := sha256.Sum256(signData)

	// Sign the credential
	signature, err := signer.Sign(ctx, hash[:], opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	// Add proof with signature
	err = vcCredential.AddCustomProof(&vcdto.Proof{
		Signature: signature,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add proof: %w", err)
	}

	// Serialize the credential to JWT string
	document, err := vcCredential.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential: %w", err)
	}

	documentBytes, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal document: %w", err)
	}

	return &AuthResponse{
		Token: string(documentBytes),
	}, nil
}

// validateAuthData validates that the required fields in AuthData are present.
func validateAuthData(data AuthData) error {
	if data.SchemaID == "" {
		return fmt.Errorf("schema ID is required")
	}

	if data.IssuerDID == "" {
		return fmt.Errorf("issuer DID is required")
	}

	if data.HolderDID == "" {
		return fmt.Errorf("holder DID is required")
	}

	return nil
}
