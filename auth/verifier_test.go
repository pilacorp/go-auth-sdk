package auth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
)

// Test helper to create a valid credential JSON with permissions
func createTestCredentialJSON(issuerDID, holderDID string, permissions []policy.Statement) []byte {
	cred := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		"id":     "urn:uuid:test-credential-123",
		"type":   []string{"VerifiableCredential", "AuthorizationCredential"},
		"issuer": issuerDID,
		"credentialSubject": map[string]interface{}{
			"id": holderDID,
		},
		"credentialSchema": map[string]interface{}{
			"id":   "https://example.com/schema/v1",
			"type": "JsonSchema",
		},
		"validFrom":  time.Now().Format(time.RFC3339),
		"validUntil": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}

	if len(permissions) > 0 {
		subject := cred["credentialSubject"].(map[string]interface{})
		subject["permissions"] = permissions
	}

	jsonData, _ := json.Marshal(cred)
	return jsonData
}

// Test helper to create a valid credential JSON with permissions and schema ID
func createTestCredentialJSONWithSchema(issuerDID, holderDID, schemaID string, permissions []policy.Statement) []byte {
	base := createTestCredentialJSON(issuerDID, holderDID, permissions)

	var cred map[string]interface{}
	_ = json.Unmarshal(base, &cred)

	cred["credentialSchema"] = map[string]interface{}{
		"id": schemaID,
	}

	jsonData, _ := json.Marshal(cred)
	return jsonData
}

// Test helper to create a valid credential JSON without permissions
func createTestCredentialJSONWithoutPermissions(issuerDID, holderDID string) []byte {
	return createTestCredentialJSON(issuerDID, holderDID, nil)
}

func TestVerify_EmptyCredential(t *testing.T) {
	_, err := Verify(context.Background(), []byte{}, WithVerifyProof())
	if err == nil {
		t.Error("Verify() should return error for empty credential")
	}
	if err.Error() != "credential is empty" {
		t.Errorf("Verify() error = %v, want 'credential is empty'", err)
	}
}

func TestVerify_InvalidJSON(t *testing.T) {
	_, err := Verify(context.Background(), []byte("invalid json"), WithVerifyProof())
	if err == nil {
		t.Error("Verify() should return error for invalid JSON")
	}
}

func TestVerifyPermissions_ValidPermissions(t *testing.T) {
	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
		{
			Effect:    policy.EffectDeny,
			Actions:   []policy.Action{policy.NewAction("Issuer:Delete")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	spec := policy.DefaultSpecification()
	err := policy.ValidateStatements(permissions, spec)
	if err != nil {
		t.Errorf("ValidateStatements() error = %v, want nil", err)
	}
}

func TestVerifyPermissions_EmptyPermissions(t *testing.T) {
	spec := policy.DefaultSpecification()
	err := policy.ValidateStatements([]policy.Statement{}, spec)
	if err == nil {
		t.Error("ValidateStatements() should return error for empty permissions")
	}
	if err.Error() != "statements list cannot be empty" {
		t.Errorf("ValidateStatements() error = %v, want 'statements list cannot be empty'", err)
	}
}

func TestVerifyPermissions_InvalidEffect(t *testing.T) {
	permissions := []policy.Statement{
		{
			Effect:    policy.Effect("invalid"),
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	spec := policy.DefaultSpecification()
	err := policy.ValidateStatements(permissions, spec)
	if err == nil {
		t.Error("ValidateStatements() should return error for invalid effect")
	}
}

func TestVerifyPermissions_NoActions(t *testing.T) {
	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	spec := policy.DefaultSpecification()
	err := policy.ValidateStatements(permissions, spec)
	if err == nil {
		t.Error("ValidateStatements() should return error when statement has no actions")
	}
}

func TestVerifyPermissions_NoResources(t *testing.T) {
	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{},
		},
	}

	spec := policy.DefaultSpecification()
	err := policy.ValidateStatements(permissions, spec)
	if err == nil {
		t.Error("ValidateStatements() should return error when statement has no resources")
	}
}

func TestVerifyPermissions_InvalidAction(t *testing.T) {
	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Invalid:Action")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	spec := policy.DefaultSpecification()
	err := policy.ValidateStatements(permissions, spec)
	if err == nil {
		t.Error("ValidateStatements() should return error for invalid action")
	}
}

func TestVerifyPermissions_InvalidResource(t *testing.T) {
	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource("InvalidResource")},
		},
	}

	spec := policy.DefaultSpecification()
	err := policy.ValidateStatements(permissions, spec)
	if err == nil {
		t.Error("ValidateStatements() should return error for invalid resource")
	}
}

func TestVerifyPermissions_WithCustomSpecification(t *testing.T) {
	// Create a custom specification with only Issuer actions and resources
	customSpec := policy.NewSpecification(
		[]policy.ActionObject{policy.ActionObjectIssuer},
		[]policy.ActionVerb{policy.ActionVerbCreate, policy.ActionVerbDelete},
		[]policy.ResourceObject{policy.ResourceObjectIssuer},
	)

	// Valid permissions for custom spec
	validPermissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	err := policy.ValidateStatements(validPermissions, customSpec)
	if err != nil {
		t.Errorf("ValidateStatements() with custom spec error = %v, want nil", err)
	}

	// Invalid permissions (action not in custom spec)
	invalidPermissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Did:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	err = policy.ValidateStatements(invalidPermissions, customSpec)
	if err == nil {
		t.Error("VerifyPermissions() should return error for action not in custom specification")
	}
}

func TestExtractCredentialData_WithPermissions(t *testing.T) {
	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	credJSON := createTestCredentialJSON(
		"did:example:issuer",
		"did:example:holder",
		permissions,
	)

	issuerDID, holderDID, _, extractedPerms, err := extractCredentialData(credJSON)
	if err != nil {
		t.Fatalf("extractCredentialData() error = %v", err)
	}

	if issuerDID != "did:example:issuer" {
		t.Errorf("extractCredentialData() issuerDID = %v, want 'did:example:issuer'", issuerDID)
	}

	if holderDID != "did:example:holder" {
		t.Errorf("extractCredentialData() holderDID = %v, want 'did:example:holder'", holderDID)
	}

	if len(extractedPerms) != 1 {
		t.Errorf("extractCredentialData() permissions len = %d, want 1", len(extractedPerms))
	}

	if extractedPerms[0].Effect != policy.EffectAllow {
		t.Errorf("extractCredentialData() permission effect = %v, want %v", extractedPerms[0].Effect, policy.EffectAllow)
	}
}

func TestExtractCredentialData_WithoutPermissions(t *testing.T) {
	credJSON := createTestCredentialJSONWithoutPermissions(
		"did:example:issuer",
		"did:example:holder",
	)

	issuerDID, holderDID, _, extractedPerms, err := extractCredentialData(credJSON)
	if err != nil {
		t.Fatalf("extractCredentialData() error = %v", err)
	}

	if issuerDID != "did:example:issuer" {
		t.Errorf("extractCredentialData() issuerDID = %v, want 'did:example:issuer'", issuerDID)
	}

	if holderDID != "did:example:holder" {
		t.Errorf("extractCredentialData() holderDID = %v, want 'did:example:holder'", holderDID)
	}

	if len(extractedPerms) != 0 {
		t.Errorf("extractCredentialData() permissions len = %d, want 0", len(extractedPerms))
	}
}

func TestExtractCredentialData_MissingIssuer(t *testing.T) {
	credJSON := createTestCredentialJSONWithoutPermissions(
		"",
		"did:example:holder",
	)

	_, _, _, _, err := extractCredentialData(credJSON)
	if err == nil {
		t.Error("extractCredentialData() should return error for missing issuer")
	}
}

func TestExtractCredentialData_MissingCredentialSubject(t *testing.T) {
	cred := map[string]interface{}{
		"issuer": "did:example:issuer",
	}
	credJSON, _ := json.Marshal(cred)

	_, _, _, _, err := extractCredentialData(credJSON)
	if err == nil {
		t.Error("extractCredentialData() should return error for missing credentialSubject")
	}
}

func TestExtractCredentialData_PermissionsAsPolicy(t *testing.T) {
	// Test when permissions are an array of statements
	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	cred := map[string]interface{}{
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":          "did:example:holder",
			"permissions": permissions,
		},
		"credentialSchema": map[string]interface{}{
			"id":   "https://example.com/schema/v1",
			"type": "JsonSchema",
		},
	}
	credJSON, _ := json.Marshal(cred)

	_, _, _, extractedPerms, err := extractCredentialData(credJSON)
	if err != nil {
		t.Fatalf("extractCredentialData() error = %v", err)
	}

	if len(extractedPerms) != 1 {
		t.Errorf("extractCredentialData() permissions len = %d, want 1", len(extractedPerms))
	}
}

func TestVerifyOptions_WithDIDBaseURL(t *testing.T) {
	opts, err := getVerifyOptions(WithDIDBaseURL("https://custom.did.url"))
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if opts.didBaseURL != "https://custom.did.url" {
		t.Errorf("WithDIDBaseURL() didBaseURL = %v, want 'https://custom.did.url'", opts.didBaseURL)
	}
}

func TestVerifyOptions_InvalidDIDBaseURL(t *testing.T) {
	testCases := []struct {
		name    string
		baseURL string
		wantErr string
	}{
		{
			name:    "invalid URL format",
			baseURL: "not-a-valid-url",
			wantErr: "didBaseURL must have http or https scheme",
		},
		{
			name:    "missing scheme",
			baseURL: "example.com/did",
			wantErr: "didBaseURL must have http or https scheme",
		},
		{
			name:    "invalid scheme",
			baseURL: "ftp://example.com/did",
			wantErr: "didBaseURL must have http or https scheme",
		},
		{
			name:    "missing host",
			baseURL: "https://",
			wantErr: "didBaseURL must have a host",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := getVerifyOptions(WithDIDBaseURL(tc.baseURL))
			if err == nil {
				t.Error("getVerifyOptions() should return error for invalid URL")
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("getVerifyOptions() error message should contain %q, got: %v", tc.wantErr, err.Error())
			}
		})
	}
}

func TestVerifyOptions_ValidURLs(t *testing.T) {
	testCases := []struct {
		name    string
		baseURL string
	}{
		{"HTTPS URL", "https://api.example.com/did"},
		{"HTTP URL", "http://localhost:8200/did"},
		{"URL with path", "https://api.ndadid.vn/api/v1/did"},
		{"URL with port", "https://api.example.com:443/did"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := getVerifyOptions(WithDIDBaseURL(tc.baseURL))
			if err != nil {
				t.Errorf("getVerifyOptions() with valid URL %q returned error: %v", tc.baseURL, err)
			}
			if opts.didBaseURL != tc.baseURL {
				t.Errorf("getVerifyOptions() didBaseURL = %v, want %v", opts.didBaseURL, tc.baseURL)
			}
		})
	}
}

func TestVerifyOptions_WithVerificationMethodKey(t *testing.T) {
	opts, err := getVerifyOptions(WithVerificationMethodKey("key-2"))
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if opts.verificationMethodKey != "key-2" {
		t.Errorf("WithVerificationMethodKey() verificationMethodKey = %v, want 'key-2'", opts.verificationMethodKey)
	}
}

func TestVerifyOptions_WithVerifyProof(t *testing.T) {
	opts, err := getVerifyOptions(WithVerifyProof())
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if !opts.isVerifyProof {
		t.Error("WithVerifyProof() verifyProof = false, want true")
	}
}

func TestVerifyOptions_WithCheckExpiration(t *testing.T) {
	opts, err := getVerifyOptions(WithCheckExpiration())
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if !opts.isCheckExpiration {
		t.Error("WithCheckExpiration() checkExpiration = false, want true")
	}
}

func TestVerifyOptions_WithCheckRevocation(t *testing.T) {
	opts, err := getVerifyOptions(WithCheckRevocation())
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if !opts.isCheckRevocation {
		t.Error("WithCheckRevocation() checkRevocation = false, want true")
	}
}

func TestVerifyOptions_WithSchemaValidation(t *testing.T) {
	opts, err := getVerifyOptions(WithSchemaValidation())
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if !opts.isValidateSchema {
		t.Error("WithSchemaValidation() validateSchema = false, want true")
	}
}

func TestVerifyOptions_WithVerifyPermissions(t *testing.T) {
	opts, err := getVerifyOptions(WithVerifyPermissions())
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if !opts.isVerifyPermissions {
		t.Error("WithVerifyPermissions() verifyPermissions = false, want true")
	}
}

func TestVerifyOptions_WithSpecification(t *testing.T) {
	customSpec := policy.NewSpecification(
		[]policy.ActionObject{policy.ActionObjectIssuer},
		[]policy.ActionVerb{policy.ActionVerbCreate},
		[]policy.ResourceObject{policy.ResourceObjectIssuer},
	)
	opts, err := getVerifyOptions(WithSpecification(customSpec))
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if opts.specification == nil {
		t.Error("WithSpecification() specification = nil, want non-nil")
	}
	if len(opts.specification.ActionObjects) != 1 {
		t.Errorf("WithSpecification() ActionObjects len = %d, want 1", len(opts.specification.ActionObjects))
	}
}

func TestVerifyOptions_WithSchemaID(t *testing.T) {
	opts, err := getVerifyOptions(WithVerifySchemaID("https://example.com/schema"))
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if opts.schemaID != "https://example.com/schema" {
		t.Errorf("WithSchemaID() schemaID = %v, want 'https://example.com/schema'", opts.schemaID)
	}
}

func TestVerifyOptions_DefaultValues(t *testing.T) {
	opts, err := getVerifyOptions()
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}
	if opts.didBaseURL != "https://api.ndadid.vn/api/v1/did" {
		t.Errorf("getVerifyOptions() default didBaseURL = %v, want 'https://api.ndadid.vn/api/v1/did'", opts.didBaseURL)
	}
	if opts.verificationMethodKey != "key-1" {
		t.Errorf("getVerifyOptions() default verificationMethodKey = %v, want 'key-1'", opts.verificationMethodKey)
	}
	if opts.isVerifyProof {
		t.Error("getVerifyOptions() default verifyProof = true, want false")
	}
	if opts.isCheckExpiration {
		t.Error("getVerifyOptions() default checkExpiration = true, want false")
	}
	if opts.isCheckRevocation {
		t.Error("getVerifyOptions() default checkRevocation = true, want false")
	}
	if opts.isValidateSchema {
		t.Error("getVerifyOptions() default validateSchema = true, want false")
	}
	if !opts.isVerifyPermissions {
		t.Error("getVerifyOptions() default verifyPermissions = false, want true")
	}
}

func TestVerifyOptions_MultipleOptions(t *testing.T) {
	opts, err := getVerifyOptions(
		WithDIDBaseURL("https://custom.url"),
		WithVerificationMethodKey("key-3"),
		WithVerifyProof(),
		WithCheckExpiration(),
	)
	if err != nil {
		t.Fatalf("getVerifyOptions() error = %v", err)
	}

	if opts.didBaseURL != "https://custom.url" {
		t.Errorf("Multiple options: didBaseURL = %v, want 'https://custom.url'", opts.didBaseURL)
	}
	if opts.verificationMethodKey != "key-3" {
		t.Errorf("Multiple options: verificationMethodKey = %v, want 'key-3'", opts.verificationMethodKey)
	}
	if !opts.isVerifyProof {
		t.Error("Multiple options: verifyProof = false, want true")
	}
	if !opts.isCheckExpiration {
		t.Error("Multiple options: checkExpiration = false, want true")
	}
}

func TestVerify_WithSchemaID_Match(t *testing.T) {
	ctx := context.Background()

	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	credJSON := createTestCredentialJSONWithSchema(
		"did:example:issuer",
		"did:example:holder",
		"https://example.com/schema",
		permissions,
	)

	// Verify with matching schema ID
	result, err := Verify(ctx, credJSON, WithVerifySchemaID("https://example.com/schema"))
	if err != nil {
		t.Fatalf("Verify() with matching schema ID error = %v, want nil", err)
	}
	if result == nil {
		t.Fatalf("Verify() result is nil, want non-nil")
	}
}

func TestVerify_WithSchemaID_Mismatch(t *testing.T) {
	ctx := context.Background()

	permissions := []policy.Statement{
		{
			Effect:    policy.EffectAllow,
			Actions:   []policy.Action{policy.NewAction("Issuer:Create")},
			Resources: []policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
		},
	}

	credJSON := createTestCredentialJSONWithSchema(
		"did:example:issuer",
		"did:example:holder",
		"https://example.com/schema",
		permissions,
	)

	// Verify with a different expected schema ID
	_, err := Verify(ctx, credJSON, WithVerifySchemaID("https://other.com/schema"))
	if err == nil {
		t.Fatalf("Verify() with mismatched schema ID error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "credential schema ID does not match expected value") {
		t.Fatalf("Verify() error = %v, want to contain 'credential schema ID does not match expected value'", err)
	}
}

func TestBuildCredentialOptions(t *testing.T) {
	verifyOpts := &verifyOptions{
		didBaseURL:            "https://test.did.url",
		verificationMethodKey: "key-test",
		isVerifyProof:         true,
		isCheckExpiration:     true,
		isCheckRevocation:     false,
		isValidateSchema:      true,
	}

	credOpts := buildCredentialOptions(verifyOpts)

	if len(credOpts) == 0 {
		t.Error("buildCredentialOptions() returned empty options")
	}

	// We can't easily test the actual option values without calling them,
	// but we can verify that options were created
	if len(credOpts) < 4 {
		t.Errorf("buildCredentialOptions() returned %d options, want at least 4", len(credOpts))
	}
}

func TestBuildCredentialOptions_EmptyBaseURL(t *testing.T) {
	verifyOpts := &verifyOptions{
		didBaseURL:            "",
		verificationMethodKey: "key-1",
		isVerifyProof:         false,
		isCheckExpiration:     false,
		isCheckRevocation:     false,
		isValidateSchema:      false,
	}

	credOpts := buildCredentialOptions(verifyOpts)

	// With empty baseURL, it should not add WithBaseURL option
	// but should still have other options if they're set
	if len(credOpts) > 0 {
		// If verificationMethodKey is set, it should add that option
		// But we can't easily verify without calling the options
	}
}
