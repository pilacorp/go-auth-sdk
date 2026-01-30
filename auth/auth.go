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

// AuthBuilder is a builder for creating and signing VC-JWT credentials with embedded permissions.
type AuthBuilder struct {
	schemaID      string
	signer        signer.Signer
	signerOptions []signer.SignOption
}

// AuthBuilderOption is a function that configures the AuthBuilder.
type AuthBuilderOption func(*AuthBuilder)

// WithBuilderSchemaID sets the schema ID for the AuthBuilder.
func WithBuilderSchemaID(schemaID string) AuthBuilderOption {
	return func(b *AuthBuilder) {
		b.schemaID = schemaID
	}
}

// WithSigner sets the signer for the AuthBuilder.
// If signer is nil, the existing signer is preserved (no-op).
func WithSigner(signer signer.Signer) AuthBuilderOption {
	return func(b *AuthBuilder) {
		if signer == nil {
			return
		}
		b.signer = signer
	}
}

// WithSignerOptions sets the signer options for the AuthBuilder.
func WithSignerOptions(opts ...signer.SignOption) AuthBuilderOption {
	return func(b *AuthBuilder) {
		b.signerOptions = opts
	}
}

// NewAuthBuilder creates a new AuthBuilder with the given options.
func NewAuthBuilder(schemaID string, opts ...AuthBuilderOption) *AuthBuilder {
	builder := &AuthBuilder{
		schemaID: schemaID,
		signer:   ecdsa.NewPrivSigner(nil),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(builder)
		}
	}

	return builder
}

// Build creates and signs the VC-JWT payload using the configured signer.
func (b *AuthBuilder) Build(ctx context.Context, data AuthData, opts ...AuthBuilderOption) (*AuthResponse, error) {
	options := b.getBuilderOptions(opts...)

	if err := validateAuthData(data, options); err != nil {
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
				ID:   options.schemaID,
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
	signature, err := options.signer.Sign(ctx, hash[:], options.signerOptions...)
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
func validateAuthData(data AuthData, options *AuthBuilder) error {
	if options.schemaID == "" {
		return fmt.Errorf("schema ID is required")
	}

	if data.IssuerDID == "" {
		return fmt.Errorf("issuer DID is required")
	}

	if data.HolderDID == "" {
		return fmt.Errorf("holder DID is required")
	}

	if len(data.CredentialStatus) == 0 {
		return fmt.Errorf("credential status is required")
	}

	return nil
}

// getBuilderOptions returns the builder options from the given options.
func (b *AuthBuilder) getBuilderOptions(opts ...AuthBuilderOption) *AuthBuilder {
	// deep copy the builder options, ensure not change the original builder
	options := &AuthBuilder{
		schemaID:      b.schemaID,
		signer:        b.signer,
		signerOptions: make([]signer.SignOption, len(b.signerOptions)),
	}
	copy(options.signerOptions, b.signerOptions)

	// Apply overrides (only affects the copy)
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	return options
}
