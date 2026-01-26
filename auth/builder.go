package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// BuilderConfig holds the builder configuration.
type BuilderConfig struct {
	issuerDID string
	schemaID  string
	signer    signer.Signer
}

// CredentialData holds the credential-specific data.
type CredentialData struct {
	holderDID  string
	policy     policy.Policy
	validFrom  *time.Time
	validUntil *time.Time
}

// CredentialBuilder builds Verifiable Credentials (VC-JWT) with embedded permission policies.
type CredentialBuilder struct {
	config BuilderConfig
}

// NewCredentialBuilder creates a new reusable CredentialBuilder.
func NewCredentialBuilder(config BuilderConfig) (*CredentialBuilder, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid builder config: %w", err)
	}

	return &CredentialBuilder{
		config: config,
	}, nil
}

// BuildResult represents the result of building a credential.
type BuildResult struct {
	JWT string
}

// Build creates the VC-JWT payload and optionally signs it if a signer is available.
func (b *CredentialBuilder) Build(ctx context.Context, data CredentialData, opts ...signer.SignOption) (*BuildResult, error) {
	// Build credential subject with permissions
	// vc.Subject has ID and CustomFields
	customFields := make(map[string]any)
	customFields["permissions"] = data.policy.Permissions

	subject := vc.Subject{
		ID:           data.holderDID,
		CustomFields: customFields,
	}

	// Build credential contents for go-credential-sdk
	subjects := []vc.Subject{subject}

	vcContents := vc.CredentialContents{
		Context: []any{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		Schemas: []vc.Schema{
			{
				ID:   b.config.schemaID,
				Type: "JsonSchema",
			},
		},
		Issuer:  b.config.issuerDID,
		Types:   []string{"VerifiableCredential", "AuthorizationCredential"},
		Subject: subjects,
	}

	// Add validity period if provided
	if data.validFrom != nil {
		vcContents.ValidFrom = *data.validFrom
	}
	if data.validUntil != nil {
		vcContents.ValidUntil = *data.validUntil
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
	signature, err := b.config.signer.Sign(ctx, hash[:], opts...)
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

	return &BuildResult{
		JWT: string(documentBytes),
	}, nil
}

// validate validates the credential configuration.
func (c *BuilderConfig) validate() error {
	if c.issuerDID == "" {
		return fmt.Errorf("issuer DID is required")
	}
	if c.schemaID == "" {
		return fmt.Errorf("schema ID is required")
	}
	if c.signer == nil {
		return fmt.Errorf("signer is required")
	}
	return nil
}
