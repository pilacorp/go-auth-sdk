package auth

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// VerifyResult represents the normalized result of credential verification.
// It contains the extracted issuer DID, holder DID, and validated permissions
// from a successfully verified credential.
type VerifyResult struct {
	IssuerDID   string             // The issuer DID from the credential
	HolderDID   string             // The holder DID from credentialSubject.id
	Permissions []policy.Statement // The extracted and validated permissions
}

// credentialSubject represents a credentialSubject object with id and optional permissions.
type credentialSubject struct {
	ID          string          `json:"id"`
	Permissions json.RawMessage `json:"permissions,omitempty"`
}

// credentialData represents the structure of credential data (without proof).
type credentialData struct {
	Issuer            string            `json:"issuer"`
	CredentialSubject credentialSubject `json:"credentialSubject"`
}

// VerifyOpt configures verification options for credential verification.
// Options can be combined to enable different verification checks.
type VerifyOpt func(*verifyOptions)

// verifyOptions holds configuration for credential verification.
// It wraps verification options from go-credential-sdk and auth SDK specific options.
type verifyOptions struct {
	// Verification options from go-credential-sdk
	didBaseURL            string
	verificationMethodKey string
	verifyProof           bool
	checkExpiration       bool
	checkRevocation       bool
	validateSchema        bool
	// Auth SDK specific options
	verifyPermissions bool
	specification     *policy.Specification
}

// WithDIDBaseURL sets the DID base URL for credential verification.
// This URL is used to resolve DID documents for proof verification.
// If not set, defaults to "https://api.ndadid.vn/api/v1/did".
func WithDIDBaseURL(baseURL string) VerifyOpt {
	return func(o *verifyOptions) {
		o.didBaseURL = baseURL
	}
}

// WithVerificationMethodKey sets the verification method key used for proof verification.
// The key identifies which verification method in the DID document to use.
// Defaults to "key-1" if not specified.
func WithVerificationMethodKey(key string) VerifyOpt {
	return func(o *verifyOptions) {
		o.verificationMethodKey = key
	}
}

// WithVerifyProof enables proof/signature verification.
// When enabled, the credential's cryptographic proof is verified against
// the issuer's public key from their DID document.
func WithVerifyProof() VerifyOpt {
	return func(o *verifyOptions) {
		o.verifyProof = true
	}
}

// WithCheckExpiration enables expiration check.
// When enabled, verifies that the credential is within its validity period
// (validFrom <= current time <= validUntil).
func WithCheckExpiration() VerifyOpt {
	return func(o *verifyOptions) {
		o.checkExpiration = true
	}
}

// WithCheckRevocation enables revocation check (optional).
// When enabled, checks the credential's revocation status using the
// credentialStatus field. This requires network access to the status registry.
func WithCheckRevocation() VerifyOpt {
	return func(o *verifyOptions) {
		o.checkRevocation = true
	}
}

// WithSchemaValidation enables schema validation.
// When enabled, validates the credential against its declared schema
// using the credentialSchema field.
func WithSchemaValidation() VerifyOpt {
	return func(o *verifyOptions) {
		o.validateSchema = true
	}
}

// WithVerifyPermissions enables permission validation.
// When enabled, validates that the permissions list extracted from the credential
// is well-formed according to the policy specification.
// Defaults to true if not specified.
func WithVerifyPermissions() VerifyOpt {
	return func(o *verifyOptions) {
		o.verifyPermissions = true
	}
}

// WithSpecification sets the policy specification for permission validation.
// If not specified, DefaultSpecification() is used.
func WithSpecification(spec policy.Specification) VerifyOpt {
	return func(o *verifyOptions) {
		o.specification = &spec
	}
}

// getVerifyOptions returns the verification options with defaults applied.
// It processes all provided options and returns a configured verifyOptions struct.
func getVerifyOptions(opts ...VerifyOpt) *verifyOptions {
	defaultSpec := policy.DefaultSpecification()
	options := &verifyOptions{
		didBaseURL:            "https://api.ndadid.vn/api/v1/did",
		verificationMethodKey: "key-1",
		verifyProof:           false,
		checkExpiration:       false,
		checkRevocation:       false,
		validateSchema:        false,
		verifyPermissions:     true,
		specification:         &defaultSpec,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	return options
}

// Verify is the main entry point for credential verification.
// It performs a comprehensive verification of a Verifiable Credential including:
//   - Parsing the credential (supports both JWT and JSON-LD formats)
//   - Validating the credential structure (required VC fields)
//   - Verifying proof/signature (if WithVerifyProof is enabled)
//   - Checking expiration (if WithCheckExpiration is enabled)
//   - Validating schema (if WithSchemaValidation is enabled)
//   - Checking revocation status (if WithCheckRevocation is enabled)
//   - Validating embedded permissions (if WithVerifyPermissions is enabled, defaults to true)
//
// The function returns a normalized VerifyResult containing the issuer DID,
// holder DID, and extracted permissions, or an error if verification fails.
//
// Example usage:
//
//	result, err := Verify(credentialBytes,
//		WithVerifyProof(),
//		WithCheckExpiration(),
//		WithDIDBaseURL("https://api.example.com/did"),
//	)
//	if err != nil {
//		// Handle verification error
//	}
//	// Use result.IssuerDID, result.HolderDID, result.Permissions
func Verify(credential []byte, opts ...VerifyOpt) (*VerifyResult, error) {
	if len(credential) == 0 {
		return nil, fmt.Errorf("credential is empty")
	}

	verifyOpts := getVerifyOptions(opts...)

	// Convert auth SDK options to credential SDK options
	credOpts := buildCredentialOptions(verifyOpts)

	// Parse credential using go-credential-sdk
	cred, err := vc.ParseCredential(credential, credOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// Get credential contents (JSON without proof)
	credData, err := cred.GetContents()
	if err != nil {
		return nil, fmt.Errorf("failed to get credential contents: %w", err)
	}

	// Extract issuer, holder, and permissions
	issuerDID, holderDID, permissions, err := extractCredentialData(credData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract credential data: %w", err)
	}

	// Verify permissions if enabled
	if verifyOpts.verifyPermissions {
		if err := verifyPermissions(permissions, *verifyOpts.specification); err != nil {
			return nil, fmt.Errorf("permissions validation failed: %w", err)
		}
	}

	return &VerifyResult{
		IssuerDID:   issuerDID,
		HolderDID:   holderDID,
		Permissions: permissions,
	}, nil
}

// verifyPermissions validates that the permissions list is well-formed.
// It performs comprehensive validation of policy statements to ensure they
// conform to the provided policy specification.
//
// Validation checks:
//   - The permissions list is not empty
//   - Each statement has a valid effect (EffectAllow or EffectDeny)
//   - Each statement has at least one action
//   - Each statement has at least one resource
//   - All actions are valid according to the provided policy specification
//   - All resources are valid according to the provided policy specification
//
// If no specification is provided, DefaultSpecification() is used.
//
// Returns an error if any validation check fails, with details about
// which statement and field caused the failure.
func verifyPermissions(permissions []policy.Statement, spec policy.Specification) error {
	if len(permissions) == 0 {
		return fmt.Errorf("permissions list cannot be empty")
	}

	// Create a policy with the provided specification to validate statements
	pol := policy.NewPolicy(
		policy.WithSpecification(spec),
		policy.WithStatements(permissions...),
	)

	// Validate the policy (this checks all statements)
	if !pol.IsValid() {
		return fmt.Errorf("invalid permissions: one or more statements are malformed")
	}

	// Additional validation: ensure each statement has required fields
	for i, stmt := range permissions {
		if stmt.Effect != policy.EffectAllow && stmt.Effect != policy.EffectDeny {
			return fmt.Errorf("permissions[%d]: invalid effect '%s'", i, stmt.Effect)
		}

		if len(stmt.Actions) == 0 {
			return fmt.Errorf("permissions[%d]: must have at least one action", i)
		}

		if len(stmt.Resources) == 0 {
			return fmt.Errorf("permissions[%d]: must have at least one resource", i)
		}
	}

	return nil
}

// extractCredentialData extracts issuer DID, holder DID, and permissions from credential data.
// It parses the credential JSON and extracts:
//   - issuerDID: From the "issuer" field
//   - holderDID: From credentialSubject.id
//   - permissions: From credentialSubject.permissions (optional, returns empty slice if absent)
//
// credentialSubject must be an object with:
//   - id: Required string field containing the holder DID
//   - permissions: Optional field containing a list of Statement objects
//
// Permissions can be provided as:
//   - An array of Statement objects directly
//
// Returns an error if the credential data is malformed or required fields are missing.
func extractCredentialData(credData []byte) (issuerDID, holderDID string, permissions []policy.Statement, err error) {
	var cred credentialData
	if err = json.Unmarshal(credData, &cred); err != nil {
		return "", "", nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	// Validate issuer
	if cred.Issuer == "" {
		return "", "", nil, fmt.Errorf("issuer must be a non-empty string")
	}
	issuerDID = cred.Issuer

	// Validate credentialSubject
	if cred.CredentialSubject.ID == "" {
		return "", "", nil, fmt.Errorf("credentialSubject.id must be a non-empty string")
	}
	holderDID = cred.CredentialSubject.ID

	// Extract permissions if present
	if len(cred.CredentialSubject.Permissions) == 0 {
		return issuerDID, holderDID, []policy.Statement{}, nil
	}

	if err = json.Unmarshal(cred.CredentialSubject.Permissions, &permissions); err != nil {
		return "", "", nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
	}

	return issuerDID, holderDID, permissions, nil
}

// buildCredentialOptions converts auth SDK verification options to credential SDK options.
// It maps the auth SDK's verifyOptions to the corresponding go-credential-sdk
// CredentialOpt functions, enabling seamless integration between the two SDKs.
//
// Only enabled options are included in the returned slice, allowing the credential
// SDK to perform only the requested verifications.
func buildCredentialOptions(opts *verifyOptions) []vc.CredentialOpt {
	var credOpts []vc.CredentialOpt

	if opts.didBaseURL != "" {
		credOpts = append(credOpts, vc.WithBaseURL(opts.didBaseURL))
	}

	if opts.verificationMethodKey != "" {
		credOpts = append(credOpts, vc.WithVerificationMethodKey(opts.verificationMethodKey))
	}

	if opts.validateSchema {
		credOpts = append(credOpts, vc.WithSchemaValidation())
	}

	if opts.verifyProof {
		credOpts = append(credOpts, vc.WithVerifyProof())
	}

	if opts.checkExpiration {
		credOpts = append(credOpts, vc.WithCheckExpiration())
	}

	if opts.checkRevocation {
		credOpts = append(credOpts, vc.WithCheckRevocation())
	}

	return credOpts
}
