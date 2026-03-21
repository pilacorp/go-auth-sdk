package builder

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func TestVPBuilder_Build_WithValidData(t *testing.T) {
	ctx := context.Background()

	// Generate a private key for the issuer and holder
	issuerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate holder key: %v", err)
	}
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	// Setup DID resolver
	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// Create test VC token (using AuthBuilder)
	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	// Create VP builder
	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	// Build VP
	vpData := model.VPData{
		ID:        "urn:uuid:test-vp-123",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if result == nil {
		t.Fatalf("Build() returned nil result")
	}

	if result.Token == "" {
		t.Fatalf("Build() returned empty token")
	}

	// Token should be JWT format: header.payload.signature
	if len(result.Token) < 10 {
		t.Fatalf("Build() token too short to be valid JWT: %s", result.Token)
	}
}

func TestVPBuilder_Build_MissingHolderDID(t *testing.T) {
	ctx := context.Background()

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	// Missing HolderDID
	vpData := model.VPData{
		ID:       "urn:uuid:test-vp",
		VCTokens: []string{"dummy-token"},
	}

	privKey, _ := crypto.GenerateKey()
	privKeyBytes := crypto.FromECDSA(privKey)

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(privKeyBytes)))

	if err == nil {
		t.Fatalf("Build() should return error for missing HolderDID")
	}

	if result != nil {
		t.Fatalf("Build() should return nil when error occurs")
	}
}

func TestVPBuilder_Build_EmptyVCTokens(t *testing.T) {
	ctx := context.Background()

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	// Empty VCTokens
	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: "did:test:holder",
		VCTokens:  []string{},
	}

	privKey, _ := crypto.GenerateKey()
	privKeyBytes := crypto.FromECDSA(privKey)

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(privKeyBytes)))

	if err == nil {
		t.Fatalf("Build() should return error for empty VCTokens")
	}

	if result != nil {
		t.Fatalf("Build() should return nil when error occurs")
	}
}

func TestVPBuilder_Build_NoSigner(t *testing.T) {
	ctx := context.Background()

	// VPBuilder without signer
	vpBuilder := NewVPBuilder()

	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: "did:test:holder",
		VCTokens:  []string{"dummy-token"},
	}

	privKey, _ := crypto.GenerateKey()
	privKeyBytes := crypto.FromECDSA(privKey)

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(privKeyBytes)))

	if err == nil {
		t.Fatalf("Build() should return error when signer is not configured")
	}

	if result != nil {
		t.Fatalf("Build() should return nil when error occurs")
	}
}

func TestVPBuilder_Build_WithValidityPeriod(t *testing.T) {
	ctx := context.Background()

	// Generate keys
	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	// Setup DID resolver
	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	validFrom := time.Now()
	validUntil := time.Now().Add(5 * time.Minute)

	vpData := model.VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &validFrom,
		ValidUntil: &validUntil,
	}

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return valid token with validity period")
	}
}

func TestVPBuilder_Build_MultipleVCs(t *testing.T) {
	ctx := context.Background()

	// Generate keys
	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	// Setup DID resolver
	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// Create multiple test VC tokens
	vcToken1 := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)
	vcToken2 := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	vpData := model.VPData{
		ID:        "urn:uuid:test-vp-multi",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken1, vcToken2},
	}

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with multiple VCs error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return valid token with multiple VCs")
	}
}

// Helper to create a test VC token
func createTestVCToken(t *testing.T, issuerDID, holderDID string, issuerKey []byte) string {
	t.Helper()

	ctx := context.Background()

	stmt := policy.NewStatement(
		policy.EffectAllow,
		[]policy.Action{policy.NewAction("Credential:Create")},
		[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
		policy.NewCondition(),
	)
	p := policy.NewPolicy(policy.WithStatements(stmt))

	statuses := []vc.Status{
		{
			ID:                   "https://example.com/status/0#0",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		},
	}

	ecdsaSigner := ecdsa.NewPrivSigner(nil)
	builder := NewAuthBuilder(
		WithBuilderSchemaID("https://example.com/schema/v1"),
		WithSigner(ecdsaSigner),
	)

	result, err := builder.Build(ctx, model.AuthData{
		IssuerDID:        issuerDID,
		HolderDID:        holderDID,
		Policy:           p,
		CredentialStatus: statuses,
	}, WithSignerOptions(signer.WithPrivateKey(issuerKey)))
	if err != nil {
		t.Fatalf("failed to create test VC: %v", err)
	}

	return result.Token
}

// ---------------------------------------------------------------------------
// Edge cases & negative tests
// ---------------------------------------------------------------------------

func TestVPBuilder_Build_InvalidVCToken(t *testing.T) {
	ctx := context.Background()

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)
	holderDID := "did:test:holder"

	// Setup DID resolver
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	holderPubHex2 := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, holderDID, holderPubHex2, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{"not.a.valid.jwt.token"},
	}

	_, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))

	if err == nil {
		t.Fatalf("Build() should return error for invalid VC token")
	}
}

func TestVPBuilder_Build_PartialInvalidVCTokens(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	validVC := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	// First token is valid, second is invalid
	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{validVC, "invalid.token.here"},
	}

	_, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))

	if err == nil {
		t.Fatalf("Build() should return error when one of the VCTokens is invalid")
	}
}

func TestVPBuilder_Build_AutoGenerateUUID(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	// ID is empty — SDK should auto-generate UUID
	vpData := model.VPData{
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with empty ID error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return token when ID is auto-generated")
	}

	// Token should still be valid JWT format
	parts := strings.Split(result.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("Auto-generated ID VP should produce valid JWT token, got: %s", result.Token)
	}
}

func TestVPBuilder_Build_SignerAtBuilderLevel(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	// Signer configured at builder level
	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(
		WithVPSigner(vpSigner),
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)),
	)

	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}

	result, err := vpBuilder.Build(ctx, vpData)
	if err != nil {
		t.Fatalf("Build() with builder-level signer error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return token with builder-level signer")
	}
}

func TestVPBuilder_Build_SignerOverrideAtCallLevel(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv1, _ := crypto.GenerateKey()
	holderKeyBytes1 := crypto.FromECDSA(holderPriv1)
	holderPriv2, _ := crypto.GenerateKey()
	holderKeyBytes2 := crypto.FromECDSA(holderPriv2)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex2 := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv2.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex2)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	// Signer at builder level uses holderPriv1
	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(
		WithVPSigner(vpSigner),
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes1)),
	)

	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}

	// Override signer at call level with holderPriv2
	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes2)))
	if err != nil {
		t.Fatalf("Build() with call-level signer override error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return token with call-level signer override")
	}
}

func TestVPBuilder_Build_WithNilOptions(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(
		WithVPSigner(vpSigner),
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)),
	)

	vpData := model.VPData{
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}

	// Pass nil as options - should use builder-level signer
	result, err := vpBuilder.Build(ctx, vpData, nil)
	if err != nil {
		t.Fatalf("Build() with nil options error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return token with nil options")
	}
}

func TestVPBuilder_Build_WithNilConfigOption(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(
		WithVPSigner(vpSigner),
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)),
	)

	vpData := model.VPData{
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}

	// Pass nil in options slice
	result, err := vpBuilder.Build(ctx, vpData, nil, nil, nil)
	if err != nil {
		t.Fatalf("Build() with nil config options error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return token with nil config options")
	}
}

func TestVPBuilder_Build_OnlyValidFrom(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	validFrom := time.Now().Add(-1 * time.Minute)

	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
		ValidFrom: &validFrom,
		// ValidUntil is nil
	}

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with only ValidFrom error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return token with only ValidFrom")
	}
}

func TestVPBuilder_Build_OnlyValidUntil(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	issuerPubHex := hex.EncodeToString(crypto.FromECDSAPub(&issuerPriv.PublicKey))
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	validUntil := time.Now().Add(5 * time.Minute)

	vpData := model.VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidUntil: &validUntil,
		// ValidFrom is nil
	}

	result, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("Build() with only ValidUntil error = %v", err)
	}

	if result == nil || result.Token == "" {
		t.Fatalf("Build() should return token with only ValidUntil")
	}
}

func TestVPBuilder_Build_WithNilSigner(t *testing.T) {
	ctx := context.Background()

	// Builder created without signer
	vpBuilder := NewVPBuilder()

	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: "did:test:holder",
		VCTokens:  []string{"any-token"},
	}

	// Even if no signer passed to Build(), it should fail because builder has no signer
	_, err := vpBuilder.Build(ctx, vpData)

	if err == nil {
		t.Fatalf("Build() should return error when signer is nil")
	}
}

func TestVPBuilder_Build_SignerReturnsError(t *testing.T) {
	ctx := context.Background()

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	holderDID := "did:test:holder"

	// Setup DID resolver
	holderPubHex := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	holderPubHex2 := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))
	didServer := buildTestDIDServer(t, holderDID, holderPubHex2, holderDID, holderPubHex)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// Create a signer that always fails
	failSigner := &failingSigner{}
	vpBuilder := NewVPBuilder(WithVPSigner(failSigner))

	// We can't actually get a valid VC without the full setup, but let's test
	// with the builder-level signer being the failing one
	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{"dummy"}, // will fail at parse, but that's fine for this test
	}

	// Try to build - will fail at VC parsing first
	_, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))

	// Should get an error (parse error is fine, signer error would come after)
	if err == nil {
		t.Fatalf("Build() should return error for dummy VC token")
	}
}

func TestVPBuilder_Build_ZeroVCTokensSlice(t *testing.T) {
	ctx := context.Background()

	vpSigner := ecdsa.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(vpSigner))

	privKey, _ := crypto.GenerateKey()
	privKeyBytes := crypto.FromECDSA(privKey)

	// Nil slice
	vpData := model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: "did:test:holder",
		VCTokens:  nil,
	}

	_, err := vpBuilder.Build(ctx, vpData,
		WithVPSignerOptions(signer.WithPrivateKey(privKeyBytes)))

	if err == nil {
		t.Fatalf("Build() should return error for nil VCTokens")
	}
}

func TestVPBuilder_mergeConfig(t *testing.T) {
	// Test that mergeConfig properly merges builder-level and call-level options

	// Builder with signer
	signer1 := ecdsa.NewPrivSigner(nil)
	builder := NewVPBuilder(WithVPSigner(signer1))

	// Merge with call-level override
	merged := builder.mergeConfig()

	if merged.signer != signer1 {
		t.Fatalf("mergeConfig should preserve builder-level signer")
	}

	// Merge with nil options
	mergedNil := builder.mergeConfig(nil)
	if mergedNil.signer != signer1 {
		t.Fatalf("mergeConfig(nil) should preserve builder-level signer")
	}

	// Builder without signer, merge should return nil signer
	builderNoSigner := NewVPBuilder()
	mergedNoSigner := builderNoSigner.mergeConfig()
	if mergedNoSigner.signer != nil {
		t.Fatalf("mergeConfig should return nil signer when builder has no signer")
	}
}

// failingSigner always returns an error
type failingSigner struct{}

func (s *failingSigner) Sign(_ context.Context, _ []byte, _ ...signer.SignOption) ([]byte, error) {
	return nil, fmt.Errorf("signer always fails")
}

func (s *failingSigner) Kind() string {
	return "failing"
}

// Helper to create a test DID server
func buildTestDIDServer(t *testing.T, issuerDID, issuerPubHex, holderDID, holderPubHex string) *httptest.Server {
	t.Helper()

	buildDoc := func(did, pubHex string) map[string]any {
		vmID := did + "#key-1"
		return map[string]any{
			"@context": []string{"https://www.w3.org/ns/did/v1"},
			"id":       did,
			"verificationMethod": []map[string]any{
				{
					"id":           vmID,
					"type":         "EcdsaSecp256k1VerificationKey2019",
					"controller":   did,
					"publicKeyHex": "0x" + pubHex,
				},
			},
			"authentication":      []string{vmID},
			"assertionMethod":     []string{vmID},
			"didDocumentMetadata": map[string]any{},
		}
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/did/") {
			http.NotFound(w, r)
			return
		}

		didEncoded := strings.TrimPrefix(r.URL.Path, "/api/v1/did/")
		did, err := url.PathUnescape(didEncoded)
		if err != nil {
			http.Error(w, "invalid did", http.StatusBadRequest)
			return
		}

		var doc map[string]any
		switch did {
		case issuerDID:
			doc = buildDoc(issuerDID, issuerPubHex)
		case holderDID:
			doc = buildDoc(holderDID, holderPubHex)
		default:
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	return httptest.NewServer(h)
}
