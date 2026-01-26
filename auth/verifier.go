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

// VerifyOpt configures verification options for credential verification.
// Options can be combined to enable different verification checks.
type VerifyOpt func(*verifyOptions)

// verifyOptions holds configuration for credential verification.
// It wraps verification options from go-credential-sdk and provides
// a unified interface for the auth SDK.
type verifyOptions struct {
	// Verification options from go-credential-sdk
	didBaseURL            string
	verificationMethodKey string
	verifyProof           bool
	checkExpiration       bool
	checkRevocation       bool
	validateSchema        bool
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

// getVerifyOptions returns the verification options with defaults applied.
// It processes all provided options and returns a configured verifyOptions struct.
func getVerifyOptions(opts ...VerifyOpt) *verifyOptions {
	options := &verifyOptions{
		didBaseURL:            "https://api.ndadid.vn/api/v1/did",
		verificationMethodKey: "key-1",
		verifyProof:           false,
		checkExpiration:       false,
		checkRevocation:       false,
		validateSchema:        false,
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
//   - Validating embedded permissions (policy statements)
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

	// Verify structure (required VC fields)
	if err := VerifyStructure(credData); err != nil {
		return nil, fmt.Errorf("structure validation failed: %w", err)
	}

	// Extract issuer, holder, and permissions
	issuerDID, holderDID, permissions, err := extractCredentialData(credData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract credential data: %w", err)
	}

	// Verify permissions
	if err := VerifyPermissions(permissions); err != nil {
		return nil, fmt.Errorf("permissions validation failed: %w", err)
	}

	// Perform credential-level verifications (proof, expiration, revocation, schema)
	if err := cred.Verify(credOpts...); err != nil {
		return nil, fmt.Errorf("credential verification failed: %w", err)
	}

	return &VerifyResult{
		IssuerDID:   issuerDID,
		HolderDID:   holderDID,
		Permissions: permissions,
	}, nil
}

// VerifyStructure validates that the credential contains all required VC fields
// as specified by the W3C Verifiable Credentials data model.
//
// Required fields:
//   - @context (or context): JSON-LD context(s) for the credential
//   - type: Must include "VerifiableCredential" in the type array or as a string
//   - issuer: The DID or URI of the credential issuer (must be non-empty)
//   - credentialSubject: The subject(s) of the credential, which must have an "id" field
//
// The credentialSubject can be:
//   - A string (just the subject ID)
//   - An object with an "id" field
//   - An array of objects, where the first object must have an "id" field
//
// Returns an error if any required field is missing or malformed.
func VerifyStructure(credentialData []byte) error {
	if len(credentialData) == 0 {
		return fmt.Errorf("credential data is empty")
	}

	var credMap map[string]interface{}
	if err := json.Unmarshal(credentialData, &credMap); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Check @context or context
	if _, hasContext := credMap["@context"]; !hasContext {
		if _, hasContext = credMap["context"]; !hasContext {
			return fmt.Errorf("missing required field: @context or context")
		}
	}

	// Check type (must include "VerifiableCredential")
	typeField, ok := credMap["type"]
	if !ok {
		return fmt.Errorf("missing required field: type")
	}

	hasVerifiableCredential := false
	switch v := typeField.(type) {
	case string:
		if v == "VerifiableCredential" {
			hasVerifiableCredential = true
		}
	case []interface{}:
		for _, t := range v {
			if tStr, ok := t.(string); ok && tStr == "VerifiableCredential" {
				hasVerifiableCredential = true
				break
			}
		}
	default:
		return fmt.Errorf("invalid type field format")
	}

	if !hasVerifiableCredential {
		return fmt.Errorf("type must include 'VerifiableCredential'")
	}

	// Check issuer
	issuer, ok := credMap["issuer"]
	if !ok {
		return fmt.Errorf("missing required field: issuer")
	}
	if issuerStr, ok := issuer.(string); !ok || issuerStr == "" {
		return fmt.Errorf("issuer must be a non-empty string")
	}

	// Check credentialSubject
	subjectField, ok := credMap["credentialSubject"]
	if !ok {
		return fmt.Errorf("missing required field: credentialSubject")
	}

	// credentialSubject can be a string (just ID), object, or array
	var subjectID string
	switch v := subjectField.(type) {
	case string:
		subjectID = v
	case map[string]interface{}:
		id, ok := v["id"]
		if !ok {
			return fmt.Errorf("credentialSubject must have 'id' field")
		}
		if idStr, ok := id.(string); !ok || idStr == "" {
			return fmt.Errorf("credentialSubject.id must be a non-empty string")
		}
		subjectID = id.(string)
	case []interface{}:
		if len(v) == 0 {
			return fmt.Errorf("credentialSubject array cannot be empty")
		}
		// Check first subject for id
		firstSubject, ok := v[0].(map[string]interface{})
		if !ok {
			return fmt.Errorf("credentialSubject array element must be an object")
		}
		id, ok := firstSubject["id"]
		if !ok {
			return fmt.Errorf("credentialSubject must have 'id' field")
		}
		if idStr, ok := id.(string); !ok || idStr == "" {
			return fmt.Errorf("credentialSubject.id must be a non-empty string")
		}
		subjectID = id.(string)
	default:
		return fmt.Errorf("invalid credentialSubject format")
	}

	if subjectID == "" {
		return fmt.Errorf("credentialSubject.id cannot be empty")
	}

	return nil
}

// VerifyPermissions validates that the permissions list is well-formed.
// It performs comprehensive validation of policy statements to ensure they
// conform to the policy specification.
//
// Validation checks:
//   - The permissions list is not empty
//   - Each statement has a valid effect (EffectAllow or EffectDeny)
//   - Each statement has at least one action
//   - Each statement has at least one resource
//   - All actions are valid according to the default policy specification
//   - All resources are valid according to the default policy specification
//
// Returns an error if any validation check fails, with details about
// which statement and field caused the failure.
func VerifyPermissions(permissions []policy.Statement) error {
	if len(permissions) == 0 {
		return fmt.Errorf("permissions list cannot be empty")
	}

	// Create a policy with default specification to validate statements
	defaultSpec := policy.DefaultSpecification()
	pol := policy.NewPolicy(
		policy.WithSpecification(defaultSpec),
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
//   - holderDID: From credentialSubject.id (or credentialSubject if it's a string)
//   - permissions: From credentialSubject.permissions (optional, returns empty slice if absent)
//
// Supports different credentialSubject formats:
//   - String: Just the holder DID, no permissions
//   - Object: Must have "id" field, may have "permissions" field
//   - Array: First element must be an object with "id" field, may have "permissions"
//
// Permissions can be provided as:
//   - An array of Statement objects directly
//   - A Policy object containing a "permissions" array
//
// Returns an error if the credential data is malformed or required fields are missing.
func extractCredentialData(credData []byte) (issuerDID, holderDID string, permissions []policy.Statement, err error) {
	var credMap map[string]interface{}
	if err = json.Unmarshal(credData, &credMap); err != nil {
		return "", "", nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	// Extract issuer
	issuer, ok := credMap["issuer"]
	if !ok {
		return "", "", nil, fmt.Errorf("missing issuer field")
	}
	issuerDID, ok = issuer.(string)
	if !ok || issuerDID == "" {
		return "", "", nil, fmt.Errorf("issuer must be a non-empty string")
	}

	// Extract credentialSubject
	subjectField, ok := credMap["credentialSubject"]
	if !ok {
		return "", "", nil, fmt.Errorf("missing credentialSubject field")
	}

	// Handle different credentialSubject formats
	var subjectObj map[string]interface{}
	switch v := subjectField.(type) {
	case string:
		holderDID = v
		// No permissions if subject is just a string
		return issuerDID, holderDID, []policy.Statement{}, nil
	case map[string]interface{}:
		subjectObj = v
	case []interface{}:
		if len(v) == 0 {
			return "", "", nil, fmt.Errorf("credentialSubject array cannot be empty")
		}
		subjectObj, ok = v[0].(map[string]interface{})
		if !ok {
			return "", "", nil, fmt.Errorf("credentialSubject array element must be an object")
		}
	default:
		return "", "", nil, fmt.Errorf("invalid credentialSubject format")
	}

	// Extract holder DID from subject
	id, ok := subjectObj["id"]
	if !ok {
		return "", "", nil, fmt.Errorf("credentialSubject missing 'id' field")
	}
	holderDID, ok = id.(string)
	if !ok || holderDID == "" {
		return "", "", nil, fmt.Errorf("credentialSubject.id must be a non-empty string")
	}

	// Extract permissions from credentialSubject.permissions
	permissionsRaw, hasPermissions := subjectObj["permissions"]
	if !hasPermissions {
		// Permissions are optional, return empty list
		return issuerDID, holderDID, []policy.Statement{}, nil
	}

	// Parse permissions
	permissionsJSON, err := json.Marshal(permissionsRaw)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to marshal permissions: %w", err)
	}

	// Unmarshal into Policy structure to get statements
	var pol policy.Policy
	if err = json.Unmarshal(permissionsJSON, &pol); err != nil {
		// Try unmarshaling as array of statements directly
		if err = json.Unmarshal(permissionsJSON, &permissions); err != nil {
			return "", "", nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
		}
	} else {
		permissions = pol.Permissions
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
