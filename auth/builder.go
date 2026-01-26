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
	IssuerDID string
	SchemaID  string
	Signer    signer.Signer
}

// CredentialData holds the credential-specific data.
type CredentialData struct {
	HolderDID  string
	Policy     policy.Policy
	ValidFrom  *time.Time
	ValidUntil *time.Time
}

// CredentialBuilder builds Verifiable Credentials (VC-JWT) with embedded permission policies.
type CredentialBuilder struct {
	Config BuilderConfig
}

// BuildResult represents the result of building a credential.
type BuildResult struct {
	token string
}

// NewCredentialBuilder creates a new reusable CredentialBuilder.
func NewCredentialBuilder(config BuilderConfig) (*CredentialBuilder, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid builder config: %w", err)
	}

	return &CredentialBuilder{
		Config: config,
	}, nil
}

// Build creates the VC-JWT payload and optionally signs it if a signer is available.
func (b *CredentialBuilder) Build(ctx context.Context, data CredentialData, opts ...signer.SignOption) (*BuildResult, error) {
	// Build credential subject with permissions
	// vc.Subject has ID and CustomFields
	customFields := make(map[string]any)
	customFields["permissions"] = data.Policy.Permissions

	subject := vc.Subject{
		ID:           data.HolderDID,
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
				ID:   b.Config.SchemaID,
				Type: "JsonSchema",
			},
		},
		Issuer:  b.Config.IssuerDID,
		Types:   []string{"VerifiableCredential", "AuthorizationCredential"},
		Subject: subjects,
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
	signature, err := b.Config.Signer.Sign(ctx, hash[:], opts...)
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
		token: string(documentBytes),
	}, nil
}

// validate validates the credential configuration.
func (c *BuilderConfig) validate() error {
	if c.IssuerDID == "" {
		return fmt.Errorf("issuer DID is required")
	}
	if c.SchemaID == "" {
		return fmt.Errorf("schema ID is required")
	}
	if c.Signer == nil {
		return fmt.Errorf("signer is required")
	}
	return nil
}
