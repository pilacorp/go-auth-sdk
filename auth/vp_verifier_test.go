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

	if len(result.VC) == 0 {
		t.Fatalf("expected non-empty VC data in result")
	}

	// Verify the VC token is correct
	if result.VC[0].Token != vcToken {
		t.Fatalf("VC token mismatch")
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
// Multiple VCs and result-structure tests
// ---------------------------------------------------------------------------

func TestVerifyPresentation_MultipleVCs(t *testing.T) {
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

	// Create multiple VCs
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

	// Multiple VCs should produce multiple tokens
	if len(result.VC) != 2 {
		t.Fatalf("expected 2 VCs, got %d", len(result.VC))
	}

	// Verify token ordering
	if result.VC[0].Token != vcToken1 || result.VC[1].Token != vcToken2 {
		t.Fatalf("VC tokens mismatch")
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

	if len(result.VC) == 0 {
		t.Fatalf("expected non-empty VC data with all options")
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

func TestExtractVCTokens(t *testing.T) {
	// Test with string tokens
	vpData := map[string]interface{}{
		"holder": "did:test:holder",
		"verifiableCredential": []interface{}{
			"token1",
			"token2",
		},
	}

	tokens, err := extractVCTokens(vpData)
	if err != nil {
		t.Fatalf("extractVCTokens() error = %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}

	if tokens[0].Token != "token1" || tokens[1].Token != "token2" {
		t.Fatalf("tokens mismatch")
	}
}

func TestExtractVCTokens_Empty(t *testing.T) {
	vpData := map[string]interface{}{
		"holder": "did:test:holder",
	}

	_, err := extractVCTokens(vpData)
	if err == nil {
		t.Fatalf("extractVCTokens() should return error for missing verifiableCredential")
	}
}

func TestExtractVCTokens_InvalidArray(t *testing.T) {
	vpData := map[string]interface{}{
		"holder":                "did:test:holder",
		"verifiableCredential": "not-an-array",
	}

	_, err := extractVCTokens(vpData)
	if err == nil {
		t.Fatalf("extractVCTokens() should return error for non-array verifiableCredential")
	}
}

func TestExtractVCTokens_ObjectVC(t *testing.T) {
	// Test that object VC (non-string) returns an error
	vcObject := map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"id":       "urn:uuid:test-vc",
		"issuer":   "did:test:issuer",
		"type":     []string{"VerifiableCredential"},
	}

	vpData := map[string]interface{}{
		"holder":                "did:test:holder",
		"verifiableCredential":   []interface{}{vcObject},
	}

	_, err := extractVCTokens(vpData)
	if err == nil {
		t.Fatalf("extractVCTokens() should return error for non-string VC")
	}
}

