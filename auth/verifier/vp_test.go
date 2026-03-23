package verifier

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
	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	ecdsasigner "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func TestVerifyPresentation_WithVPResolver(t *testing.T) {
	ctx := context.Background()

	issuerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}
	holderPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate holder key: %v", err)
	}

	issuerKeyBytes := crypto.FromECDSA(issuerPriv)
	holderKeyBytes := crypto.FromECDSA(holderPriv)
	holderPublicKey := hex.EncodeToString(crypto.FromECDSAPub(&holderPriv.PublicKey))

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vc.Init(didBaseURL)
	vp.Init(didBaseURL)

	vpToken := createTestPresentationToken(t, ctx, issuerDID, holderDID, issuerKeyBytes, holderKeyBytes)

	resolver, err := verificationmethod.NewStaticResolver(holderPublicKey)
	if err != nil {
		t.Fatalf("failed to create static resolver: %v", err)
	}

	result, err := VerifyPresentation(ctx, []byte(vpToken),
		WithVPVerifyProof(),
		WithVPResolver(resolver),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() with resolver error = %v", err)
	}

	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}
	if len(result.VCs) != 1 {
		t.Fatalf("expected 1 VC, got %d", len(result.VCs))
	}
}

func TestVerifyPresentation_WithVPResolverBaseURL(t *testing.T) {
	ctx := context.Background()

	issuerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}
	holderPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate holder key: %v", err)
	}

	issuerKeyBytes := crypto.FromECDSA(issuerPriv)
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vc.Init(didBaseURL)
	vp.Init(didBaseURL)

	vpToken := createTestPresentationToken(t, ctx, issuerDID, holderDID, issuerKeyBytes, holderKeyBytes)

	result, err := VerifyPresentation(ctx, []byte(vpToken),
		WithVPVerifyProof(),
		WithVPDIDBaseURL(didBaseURL),
		WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		t.Fatalf("VerifyPresentation() with DID base URL error = %v", err)
	}

	if result.HolderDID != holderDID {
		t.Fatalf("HolderDID mismatch: got %q, want %q", result.HolderDID, holderDID)
	}
}

func TestVerifyPresentation_ValidPresentation(t *testing.T) {
	ctx := context.Background()

	issuerPriv, _ := crypto.GenerateKey()
	issuerKeyBytes := crypto.FromECDSA(issuerPriv)

	holderPriv, _ := crypto.GenerateKey()
	holderKeyBytes := crypto.FromECDSA(holderPriv)

	issuerDID := "did:test:issuer"
	holderDID := "did:test:holder"

	// Create test DID server
	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// Create VP
	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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

	if len(result.VCs) == 0 {
		t.Fatalf("expected non-empty VC data in result")
	}

	// Verify the VC token is correct
	if result.VCs[0].Token != vcToken {
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

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	validFrom := time.Now()
	validUntil := time.Now().Add(5 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &validFrom,
		ValidUntil: &validUntil,
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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

func createTestPresentationToken(t *testing.T, ctx context.Context, issuerDID, holderDID string, issuerKeyBytes, holderKeyBytes []byte) string {
	t.Helper()

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	vpBuilder := builder.NewVPBuilder(
		builder.WithVPSigner(ecdsasigner.NewPrivSigner(nil)),
	)

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
	if err != nil {
		t.Fatalf("failed to build VP: %v", err)
	}

	return vpResp.Token
}

func createTestVCToken(t *testing.T, issuerDID, holderDID string, issuerKeyBytes []byte) string {
	t.Helper()

	ctx := context.Background()

	authBuilder := builder.NewAuthBuilder(
		builder.WithBuilderSchemaID("https://example.com/schema/v1"),
		builder.WithSigner(ecdsasigner.NewPrivSigner(nil)),
	)

	vcResp, err := authBuilder.Build(ctx, model.AuthData{
		ID:        "urn:uuid:test-vc",
		IssuerDID: issuerDID,
		HolderDID: holderDID,
		Policy: policy.NewPolicy(
			policy.WithStatements(
				policy.NewStatement(
					policy.EffectAllow,
					[]policy.Action{policy.NewAction("Issuer:Create")},
					[]policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
					policy.NewCondition(),
				),
			),
		),
		CredentialStatus: []vc.Status{
			{
				ID:                   "https://example.com/status/0#0",
				Type:                 "StatusList2021Entry",
				StatusPurpose:        "revocation",
				StatusListIndex:      "0",
				StatusListCredential: "https://example.com/status/0",
			},
		},
	}, builder.WithSignerOptions(signer.WithPrivateKey(issuerKeyBytes)))
	if err != nil {
		t.Fatalf("failed to build VC: %v", err)
	}

	return vcResp.Token
}

func newVPTestDIDServer(t *testing.T, issuerDID string, issuerKey []byte, holderDID string, holderKey []byte) *httptest.Server {
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

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	// VP with already-expired validity window
	pastTime := time.Now().Add(-10 * time.Minute)
	validUntil := time.Now().Add(-1 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &pastTime,
		ValidUntil: &validUntil,
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	// VP with future ValidFrom
	futureTime := time.Now().Add(10 * time.Minute)
	validUntil := time.Now().Add(20 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &futureTime,
		ValidUntil: &validUntil,
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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
	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	// Create multiple VCs
	vcToken1 := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)
	vcToken2 := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:        "urn:uuid:test-vp-multi",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken1, vcToken2},
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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
	if len(result.VCs) != 2 {
		t.Fatalf("expected 2 VCs, got %d", len(result.VCs))
	}

	// Verify token ordering
	if result.VCs[0].Token != vcToken1 || result.VCs[1].Token != vcToken2 {
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

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	validFrom := time.Now()
	validUntil := time.Now().Add(5 * time.Minute)

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:         "urn:uuid:test-vp",
		HolderDID:  holderDID,
		VCTokens:   []string{vcToken},
		ValidFrom:  &validFrom,
		ValidUntil: &validUntil,
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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

	if len(result.VCs) == 0 {
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

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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

	didServer := newVPTestDIDServer(t, issuerDID, issuerKeyBytes, holderDID, holderKeyBytes)
	defer didServer.Close()

	didBaseURL := didServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)

	vcToken := createTestVCToken(t, issuerDID, holderDID, issuerKeyBytes)

	ecdsaSigner := ecdsasigner.NewPrivSigner(nil)
	vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsaSigner))

	vpResp, err := vpBuilder.Build(ctx, model.VPData{
		ID:        "urn:uuid:test-vp",
		HolderDID: holderDID,
		VCTokens:  []string{vcToken},
	}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderKeyBytes)))
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
	opts, err := getVPVerifyOptions()
	if err != nil {
		t.Fatalf("getVPVerifyOptions() error = %v", err)
	}

	if opts.didBaseURL != "https://api.ndadid.vn/api/v1/did" {
		t.Fatalf("expected default DID base URL, got %q", opts.didBaseURL)
	}

	if opts.verificationMethodKey != "key-1" {
		t.Fatalf("expected default verification method key 'key-1', got %q", opts.verificationMethodKey)
	}
}

func TestGetVPVerifyOptions_Override(t *testing.T) {
	opts, err := getVPVerifyOptions(
		WithVPDIDBaseURL("https://custom.did/api/v1/did"),
		WithVPVerificationMethodKey("my-key"),
		WithVPVerifyProof(),
		WithVPCheckExpiration(),
	)
	if err != nil {
		t.Fatalf("getVPVerifyOptions() error = %v", err)
	}

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
	opts, err := getVPVerifyOptions(nil, nil)
	if err != nil {
		t.Fatalf("getVPVerifyOptions() error = %v", err)
	}

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
	vpData := model.PresentationData{
		Holder:               "did:test:holder",
		VerifiableCredential: []string{"token1", "token2"},
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
	vpData := model.PresentationData{
		Holder: "did:test:holder",
	}

	_, err := extractVCTokens(vpData)
	if err == nil {
		t.Fatalf("extractVCTokens() should return error for missing verifiableCredential")
	}
}

func TestExtractVCTokens_ObjectVC(t *testing.T) {
	vpJSON := []byte(`{"holder":"did:test:holder","verifiableCredential":[{"id":"urn:uuid:test-vc"}]}`)

	var vpData model.PresentationData
	if err := json.Unmarshal(vpJSON, &vpData); err == nil {
		t.Fatalf("json.Unmarshal() should return error for object VC when PresentationData expects []string")
	}
}
