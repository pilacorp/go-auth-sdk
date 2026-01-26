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

// CredentialOption configures a CredentialBuilder during construction.
type CredentialOption func(*credentialOptions)

// credentialOptions holds all the options for building a credential.
type credentialOptions struct {
	signer     signer.Signer
	issuerDID  string
	holderDID  string
	schemaID   string
	validFrom  *time.Time
	validUntil *time.Time
	policy     *policy.Policy
}

// CredentialBuilder builds Verifiable Credentials (VC-JWT) with embedded permission policies.
type CredentialBuilder struct {
	options credentialOptions
}

// NewCredentialBuilder creates a new CredentialBuilder with the given options.
func NewCredentialBuilder(opts ...CredentialOption) *CredentialBuilder {
	options := credentialOptions{
		policy: &policy.Policy{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return &CredentialBuilder{
		options: options,
	}
}

// WithSigner sets the signing signer for the credential.
func WithSigner(s signer.Signer) CredentialOption {
	return func(o *credentialOptions) {
		o.signer = s
	}
}

// WithIssuer sets the issuer DID.
func WithIssuer(issuerDID string) CredentialOption {
	return func(o *credentialOptions) {
		o.issuerDID = issuerDID
	}
}

// WithHolder sets the holder DID (subject).
func WithHolder(holderDID string) CredentialOption {
	return func(o *credentialOptions) {
		o.holderDID = holderDID
	}
}

// WithSchemaID sets the schema ID for the credential.
func WithSchemaID(schemaID string) CredentialOption {
	return func(o *credentialOptions) {
		o.schemaID = schemaID
	}
}

// WithPolicy sets the policy for the credential.
func WithPolicy(p policy.Policy) CredentialOption {
	return func(o *credentialOptions) {
		o.policy = &p
	}
}

// WithExpiration sets the validity period for the credential.
func WithExpiration(validFrom, validUntil time.Time) CredentialOption {
	return func(o *credentialOptions) {
		o.validFrom = &validFrom
		o.validUntil = &validUntil
	}
}

// BuildResult represents the result of building a credential.
type BuildResult struct {
	JWT string
}

// Build creates the VC-JWT payload and optionally signs it if a signer is available.
func (b *CredentialBuilder) Build(ctx context.Context, opts ...signer.SignOption) (*BuildResult, error) {
	// Validate required fields
	if b.options.issuerDID == "" {
		return nil, fmt.Errorf("issuer DID is required")
	}
	if b.options.holderDID == "" {
		return nil, fmt.Errorf("holder DID is required")
	}
	if b.options.policy == nil || b.options.policy.IsEmpty() {
		return nil, fmt.Errorf("policy with at least one statement is required")
	}

	// Build credential subject with permissions
	// vc.Subject has ID and CustomFields
	customFields := make(map[string]any)
	customFields["permissions"] = b.options.policy.Permissions

	subject := vc.Subject{
		ID:           b.options.holderDID,
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
				ID:   b.options.schemaID,
				Type: "JsonSchema",
			},
		},
		Issuer:  b.options.issuerDID,
		Types:   []string{"VerifiableCredential", "AuthorizationCredential"},
		Subject: subjects,
	}

	// Add validity period if provided
	if b.options.validFrom != nil {
		vcContents.ValidFrom = *b.options.validFrom
	}
	if b.options.validUntil != nil {
		vcContents.ValidUntil = *b.options.validUntil
	}

	// Create JWT credential
	vcCredential, err := vc.NewJWTCredential(vcContents)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT credential: %w", err)
	}

	// If signer is available, sign the credential
	if b.options.signer != nil {
		// Get signing input
		signData, err := vcCredential.GetSigningInput()
		if err != nil {
			return nil, fmt.Errorf("failed to get signing input: %w", err)
		}

		// Hash the signing data
		hash := sha256.Sum256(signData)

		// Sign using the signer
		signature, err := b.options.signer.Sign(ctx, hash[:], opts...)
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
