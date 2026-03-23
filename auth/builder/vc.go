// Package builder provides APIs for building and signing authorization credentials and presentations.
// It supports both local private key and Vault-backed signers through the signer abstraction.
// The package provides:
//   - AuthBuilder: A builder for creating and signing VC-JWT credentials with embedded permissions
//   - VPBuilder: A builder for creating and signing VP-JWT presentations with embedded VC tokens
//   - Builder options: Configurable options for schema IDs, signer implementations, and signer options
package builder

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// VCBuilderConfig is a configuration for the AuthBuilder.
type VCBuilderConfig struct {
	// Credential configuration
	schemaID string

	// Signing configuration (could be separate)
	signer        signer.Signer
	signerOptions []signer.SignOption
}

// VCBuilder is a builder for creating and signing VC-JWT credentials with embedded permissions.
type VCBuilder struct {
	config *VCBuilderConfig
}

// VCBuilderConfigOption is a function that configures the VCBuilderConfig.
type VCBuilderConfigOption func(*VCBuilderConfig)

// WithVCBuilderSchemaID sets the schema ID for the VCBuilder.
func WithVCBuilderSchemaID(schemaID string) VCBuilderConfigOption {
	return func(b *VCBuilderConfig) {
		b.schemaID = schemaID
	}
}

// WithVCSignerOptions sets the signer options for the VCBuilder.
func WithVCSignerOptions(opts ...signer.SignOption) VCBuilderConfigOption {
	return func(b *VCBuilderConfig) {
		b.signerOptions = opts
	}
}

// WithVCSigner sets the signer for the VCBuilder.
func WithVCSigner(signer signer.Signer) VCBuilderConfigOption {
	return func(b *VCBuilderConfig) {
		if signer != nil {
			b.signer = signer
		}
	}
}

// NewVCBuilder creates a new VCBuilder with the given config options“.
func NewVCBuilder(opts ...VCBuilderConfigOption) *VCBuilder {
	config := &VCBuilderConfig{
		signer: ecdsa.NewPrivSigner(nil),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(config)
		}
	}

	return &VCBuilder{
		config: config,
	}
}

// Build creates and signs the VC-JWT payload using the configured signer.
func (b *VCBuilder) Build(ctx context.Context, data model.VCData, opts ...VCBuilderConfigOption) (*model.VCResponse, error) {
	options := b.mergeConfig(opts...)

	if err := validateVCData(data, options); err != nil {
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
	tokenStr, err := vcCredential.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential: %w", err)
	}

	token, ok := tokenStr.(string)
	if !ok {
		return nil, fmt.Errorf("invalid token type: expected string")
	}

	return &model.VCResponse{
		Token: token,
	}, nil
}

// validateVCData validates that the required fields in model.AuthData are present.
func validateVCData(data model.VCData, options *VCBuilderConfig) error {
	if options.schemaID == "" {
		return fmt.Errorf("schema ID is required")
	}

	if options.signer == nil {
		return fmt.Errorf("signer is required")
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

	if len(data.Policy.Permissions) == 0 {
		return fmt.Errorf("permissions are required")
	}

	return nil
}

// mergeConfig merges the options into the builder config.
func (b *VCBuilder) mergeConfig(opts ...VCBuilderConfigOption) *VCBuilderConfig {
	// merge the options into the builder config
	options := &VCBuilderConfig{
		schemaID:      b.config.schemaID,
		signer:        b.config.signer,
		signerOptions: make([]signer.SignOption, len(b.config.signerOptions)),
	}
	copy(options.signerOptions, b.config.signerOptions)

	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	return options
}
