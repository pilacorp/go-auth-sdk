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
	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// VPBuilderConfig is a configuration for the VPBuilder.
type VPBuilderConfig struct {
	signer        signer.Signer
	signerOptions []signer.SignOption
}

// VPBuilder is a builder for creating and signing Verifiable Presentations with embedded VCs.
type VPBuilder struct {
	config *VPBuilderConfig
}

// VPBuilderConfigOption is a function that configures the VPBuilderConfig.
type VPBuilderConfigOption func(*VPBuilderConfig)

// WithVPSigner sets the signer for the VPBuilder.
func WithVPSigner(signer signer.Signer) VPBuilderConfigOption {
	return func(b *VPBuilderConfig) {
		if signer != nil {
			b.signer = signer
		}
	}
}

// WithVPSignerOptions sets the signer options for the VPBuilder.
func WithVPSignerOptions(opts ...signer.SignOption) VPBuilderConfigOption {
	return func(b *VPBuilderConfig) {
		b.signerOptions = opts
	}
}

// NewVPBuilder creates a new VPBuilder with the given config options.
func NewVPBuilder(opts ...VPBuilderConfigOption) *VPBuilder {
	config := &VPBuilderConfig{}

	for _, opt := range opts {
		if opt != nil {
			opt(config)
		}
	}

	return &VPBuilder{
		config: config,
	}
}

// Build creates and signs a Verifiable Presentation containing the provided VCs.
// It combines multiple VC tokens into a single VP, signs it with the holder's private key,
// and returns the VP-JWT token.
func (b *VPBuilder) Build(ctx context.Context, data model.VPData, opts ...VPBuilderConfigOption) (*model.VPResponse, error) {
	options := b.mergeConfig(opts...)

	if err := validateVPData(data, options); err != nil {
		return nil, err
	}

	// Parse all VC tokens into vc.Credential objects
	credentials := make([]vc.Credential, 0, len(data.VCTokens))
	for i, token := range data.VCTokens {
		credential, err := vc.ParseCredential([]byte(token))
		if err != nil {
			return nil, fmt.Errorf("failed to parse vc token at index %d: %w", i, err)
		}
		credentials = append(credentials, credential)
	}

	// Build presentation ID if not provided
	if data.ID == "" {
		data.ID = uuid.NewString()
	}

	// Build presentation contents
	contents := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    data.ID,
		Types:                 []string{"VerifiablePresentation"},
		Holder:                data.HolderDID,
		VerifiableCredentials: credentials,
	}

	// Set optional validity fields
	if data.ValidFrom != nil {
		contents.ValidFrom = *data.ValidFrom
	}
	if data.ValidUntil != nil {
		contents.ValidUntil = *data.ValidUntil
	}

	// Create JWT presentation
	presentation, err := vp.NewJWTPresentation(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT presentation: %w", err)
	}

	// Sign the credential
	// Get signing input
	signData, err := presentation.GetSigningInput()
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
	err = presentation.AddCustomProof(&vcdto.Proof{
		Signature: signature,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add proof: %w", err)
	}

	// Serialize the credential to JWT string
	tokenStr, err := presentation.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential: %w", err)
	}

	token, ok := tokenStr.(string)
	if !ok {
		return nil, fmt.Errorf("invalid token type: expected string")
	}

	return &model.VPResponse{
		Token: token,
	}, nil
}

// validateVPData validates that the required fields in VPData are present.
func validateVPData(data model.VPData, options *VPBuilderConfig) error {
	if data.HolderDID == "" {
		return fmt.Errorf("holder DID is required")
	}

	if len(data.VCTokens) == 0 {
		return fmt.Errorf("at least one VC token is required")
	}

	if options.signer == nil {
		return fmt.Errorf("signer is required")
	}

	return nil
}

// mergeConfig merges the options into the builder config.
func (b *VPBuilder) mergeConfig(opts ...VPBuilderConfigOption) *VPBuilderConfig {
	// merge the options into the builder config
	options := &VPBuilderConfig{
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
