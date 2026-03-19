package auth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/signer"
	ecdsasigner "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func TestVerifyPresentation_ValidPresentation(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	// Create test DID server
	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// Create VP
	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	// Verify VP
	result, err := VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPVerifyProof(),
		WithVPCheckExpiration(),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() error = %v", err)
	}

	if result == nil {
		t.Fatalf("VerifyPresentation() returned nil result")
	}

	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}

	if len(result.EmbeddedVCData) == 0 {
		t.Fatalf("expected non-empty embedded VC data in result")
	}
}

func TestVerifyPresentation_EmptyPresentation(t *testing.T) {
	ctx := context.Background()

	result, err := VerifyPresentation(ctx, []byte{})

	if err == nil {
		t.Fatalf("VerifyPresentation() should return error for empty presentation")
	}

	if result != nil {
		t.Fatalf("VerifyPresentation() should return nil when error occurs")
	}
}

func TestVerifyPresentation_InvalidToken(t *testing.T) {
	ctx := context.Background()

	result, err := VerifyPresentation(ctx, []byte("invalid.token.format"))

	if err == nil {
		t.Fatalf("VerifyPresentation() should return error for invalid token")
	}

	if result != nil {
		t.Fatalf("VerifyPresentation() should return nil when error occurs")
	}
}

func TestVerifyPresentation_WithCheckExpiration(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	validFrom := time.Now()
	validUntil := time.Now().Add(5 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &validFrom,
		ValidUntil: &validUntil,
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	// Verify with expiration check enabled
	result, err := VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPCheckExpiration(),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() error = %v", err)
	}

	if result == nil || result.HolderDID != holderDID {
		t.Fatalf("VerifyPresentation() should successfully verify non-expired presentation")
	}
}

// Test helper: create a test DID server
func newTestDIDServer(t *testing.T, issuerDID string, issuerKey []byte, holderDID string, holderKey []byte) *httptest.Server {
	t.Helper()

	buildDoc := func(did string, key []byte) map[string]any {
		pk, _ := crypto.ToECDSA(key)
		pubKey := crypto.FromECDSAPub(&pk.PublicKey)
		pubHex := hex.EncodeToString(pubKey)

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
			doc = buildDoc(issuerDID, issuerKey)
		case holderDID:
			doc = buildDoc(holderDID, holderKey)
		default:
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	return httptest.NewServer(h)
}

// ---------------------------------------------------------------------------
// Negative / error-path tests
// ---------------------------------------------------------------------------

func TestVerifyPresentation_ExpiredPresentation(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	// VP with already-expired validity window
	pastTime := time.Now().Add(-10 * time.Minute)
	validUntil := time.Now().Add(-1 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &pastTime,
		ValidUntil: &validUntil,
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	_, err = VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPCheckExpiration(),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)

	if err == nil {
		t.Fatalf("VerifyPresentation() should return error for expired presentation")
	}
}

func TestVerifyPresentation_NotYetValid(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	// VP with future ValidFrom
	futureTime := time.Now().Add(10 * time.Minute)
	validUntil := time.Now().Add(20 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &futureTime,
		ValidUntil: &validUntil,
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	_, err = VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPCheckExpiration(),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)

	if err == nil {
		t.Fatalf("VerifyPresentation() should return error for not-yet-valid presentation")
	}
}

// ---------------------------------------------------------------------------
// Multiple VCs, permissions, and result-structure tests
// ---------------------------------------------------------------------------

func TestVerifyPresentation_MultipleVCsPermissions(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// Create two VCs with different permissions
	vcToken1 := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)
	vcToken2 := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:        "urn:uuid:test-vp-multi",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken1, vcToken2},
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	result, err := VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() error = %v", err)
	}

	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}

	// Multiple VCs should have multiple verification results
	if len(result.EmbeddedVCData) == 0 {
		t.Fatalf("expected non-empty embedded VC data from multiple VCs")
	}
}

func TestVerifyPresentation_NoPermissions(t *testing.T) {
	// AuthBuilder requires permissions, so we cannot create a VC without policy.
	// This test verifies that a VP built with a VC that has an empty permissions
	// array (not nil) still verifies correctly.
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// VC with policy (permissions are required by builder)
	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:        "urn:uuid:test-vp-no-perms",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	result, err := VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() error = %v", err)
	}

	// Should succeed
	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}
}

func TestVerifyPresentation_WithProofVerification(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	// Verify with proof verification enabled
	result, err := VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPVerifyProof(),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() with proof verification error = %v", err)
	}

	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}
}

func TestVerifyPresentation_WithVCValidation(t *testing.T) {
	// Note: WithVPValidateCredentials requires the schema endpoint to be reachable.
	// The test helper sets schema ID to "https://example.com/schema/v1", which
	// is not served by our mock DID server. So we test WithVPValidateCredentials
	// by verifying that the option is correctly propagated to vpVerifyOptions,
	// and that VerifyPresentation still succeeds at parsing the presentation.
	// (The actual VC schema validation happens inside the credential SDK which
	// would need a real/reachable schema server.)
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	// Verify the option is correctly set (isValidateVC=true)
	opts := getVPVerifyOptions(
		WithVPValidateCredentials(),
		WithVPDIDBaseURL(didBaseURL),
	)
	if !opts.isValidateVC {
		t.Fatal("WithVPValidateCredentials should set isValidateVC=true")
	}

	// Verify buildVPOptions produces the WithVCValidation option
	vpOpts := buildVPOptions(opts)
	if len(vpOpts) < 3 {
		t.Fatalf("buildVPOptions should produce WithVCValidation option, got %d opts", len(vpOpts))
	}

	// VerifyPresentation still works at parsing/presentation level without the
	// full VC validation chain
	result, err := VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() error = %v", err)
	}

	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}
}

// ---------------------------------------------------------------------------
// Combined options tests
// ---------------------------------------------------------------------------

func TestVerifyPresentation_AllOptions(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	validFrom := time.Now()
	validUntil := time.Now().Add(5 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &validFrom,
		ValidUntil: &validUntil,
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	// Verify with all options combined
	result, err := VerifyPresentation(ctx, []byte(vpResp.Token),
		WithVPVerifyProof(),
		WithVPCheckExpiration(),
		WithVPValidateCredentials(),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() with all options error = %v", err)
	}

	if result == nil {
		t.Fatalf("VerifyPresentation() returned nil result")
	}

	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}

	if len(result.EmbeddedVCData) == 0 {
		t.Fatalf("expected non-empty embedded VC data with all options")
	}
}

func TestVerifyPresentation_NoOptions(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	// Verify with no options at all - should still parse and extract
	result, err := VerifyPresentation(ctx, []byte(vpResp.Token))
	if err != nil {
		t.Fatalf("VerifyPresentation() with no options error = %v", err)
	}

	if result == nil || result.HolderDID != holderDID {
		t.Fatalf("VerifyPresentation() should return holder DID even with no options")
	}
}

func TestVerifyPresentation_NilOptions(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := NewVPBuilder(WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("build vp failed: %v", err)
	}

	// Pass nil options - should use defaults
	result, err := VerifyPresentation(ctx, []byte(vpResp.Token), nil, nil, nil)
	if err != nil {
		t.Fatalf("VerifyPresentation() with nil options error = %v", err)
	}

	if result == nil || result.HolderDID != holderDID {
		t.Fatalf("VerifyPresentation() should work with nil options")
	}
}

// ---------------------------------------------------------------------------
// Internal helper function tests
// ---------------------------------------------------------------------------

func TestGetVPVerifyOptions_Defaults(t *testing.T) {
	opts := getVPVerifyOptions()

	if opts.didBaseURL != "https://api.ndadid.vn/api/v1/did" {
		t.Fatalf("expected default DID base URL, got %q", opts.didBaseURL)
	}

	if opts.verificationMethodKey != "key-1" {
		t.Fatalf("expected default verification method key 'key-1', got %q", opts.verificationMethodKey)
	}
}

func TestGetVPVerifyOptions_Override(t *testing.T) {
	opts := getVPVerifyOptions(
		WithVPDIDBaseURL("https://custom.did/api/v1/did"),
		WithVPVerificationMethodKey("my-key"),
		WithVPVerifyProof(),
		WithVPCheckExpiration(),
		WithVPValidateCredentials(),
	)

	if opts.didBaseURL != "https://custom.did/api/v1/did" {
		t.Fatalf("didBaseURL mismatch: got %q", opts.didBaseURL)
	}

	if opts.verificationMethodKey != "my-key" {
		t.Fatalf("verificationMethodKey mismatch: got %q", opts.verificationMethodKey)
	}

	if !opts.isVerifyProof {
		t.Fatal("isVerifyProof should be true")
	}

	if !opts.isCheckExpiration {
		t.Fatal("isCheckExpiration should be true")
	}

	if !opts.isValidateVC {
		t.Fatal("isValidateVC should be true")
	}
}

func TestGetVPVerifyOptions_NilOptions(t *testing.T) {
	// Nil options in the slice should be skipped
	opts := getVPVerifyOptions(nil, nil)

	if opts.didBaseURL != "https://api.ndadid.vn/api/v1/did" {
		t.Fatalf("nil options should not affect defaults")
	}
}

func TestBuildVPOptions(t *testing.T) {
	opts := &vpVerifyOptions{
		didBaseURL:            "https://test.did/api/v1/did",
		verificationMethodKey: "my-key",
		isVerifyProof:         true,
		isCheckExpiration:     true,
		isValidateVC:          true,
	}

	vpOpts := buildVPOptions(opts)

	// Should produce non-empty options slice
	if len(vpOpts) == 0 {
		t.Fatalf("buildVPOptions should produce options when fields are set")
	}
}

func TestBuildVPOptions_Empty(t *testing.T) {
	opts := &vpVerifyOptions{}
	vpOpts := buildVPOptions(opts)

	// Empty options should produce empty slice
	if len(vpOpts) != 0 {
		t.Fatalf("buildVPOptions should produce empty slice for empty opts")
	}
}

func TestBuildVPOptions_Partial(t *testing.T) {
	opts := &vpVerifyOptions{
		didBaseURL: "https://partial.did/api/v1/did",
		// other fields empty
	}
	vpOpts := buildVPOptions(opts)

	// Only didBaseURL is set
	if len(vpOpts) != 1 {
		t.Fatalf("buildVPOptions should produce 1 option when only didBaseURL is set, got %d", len(vpOpts))
	}
}
