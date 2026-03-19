// Package auth provides VP verification for validating Verifiable Presentations.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// VPVerifyOpt configures verification options for presentation verification.
type VPVerifyOpt func(*vpVerifyOptions)

// vpVerifyOptions holds configuration for presentation verification.
type vpVerifyOptions struct {
	didBaseURL            string
	verificationMethodKey string
	isVerifyProof         bool
	isCheckExpiration     bool
	isValidateVC          bool
	isVerifyAudience      bool
	isVerifyNonce         bool
	expectedAudience      string
	expectedNonce         string
}

// WithVPDIDBaseURL sets the DID base URL for presentation verification.
// This URL is used to resolve DID documents for proof verification.
// If not set, defaults to "https://api.ndadid.vn/api/v1/did".
func WithVPDIDBaseURL(baseURL string) VPVerifyOpt {
	return func(o *vpVerifyOptions) {
		o.didBaseURL = baseURL
	}
}

// WithVPVerificationMethodKey sets the verification method key used for proof verification.
// The key identifies which verification method in the DID document to use.
// Defaults to "key-1" if not specified.
func WithVPVerificationMethodKey(key string) VPVerifyOpt {
	return func(o *vpVerifyOptions) {
		o.verificationMethodKey = key
	}
}

// WithVPVerifyProof enables VP proof/signature verification.
// When enabled, the presentation's cryptographic proof is verified against
// the holder's public key from their DID document.
func WithVPVerifyProof() VPVerifyOpt {
	return func(o *vpVerifyOptions) {
		o.isVerifyProof = true
	}
}

// WithVPCheckExpiration enables expiration check for the presentation.
// When enabled, verifies that the presentation is within its validity period
// (validFrom <= current time <= validUntil).
func WithVPCheckExpiration() VPVerifyOpt {
	return func(o *vpVerifyOptions) {
		o.isCheckExpiration = true
	}
}

// WithVPValidateCredentials enables validation of embedded VCs in the presentation.
// When enabled, all embedded credentials are parsed and validated.
func WithVPValidateCredentials() VPVerifyOpt {
	return func(o *vpVerifyOptions) {
		o.isValidateVC = true
	}
}

// WithVPVerifyAudience enables audience verification.
// When enabled, the presentation's audience claim (if present) must match the expected value.
func WithVPVerifyAudience(audience string) VPVerifyOpt {
	return func(o *vpVerifyOptions) {
		o.isVerifyAudience = true
		o.expectedAudience = audience
	}
}

// WithVPVerifyNonce enables nonce verification for replay protection.
// When enabled, the presentation's nonce claim (if present) must match the expected value.
func WithVPVerifyNonce(nonce string) VPVerifyOpt {
	return func(o *vpVerifyOptions) {
		o.isVerifyNonce = true
		o.expectedNonce = nonce
	}
}

// VerifyPresentation performs comprehensive verification of a Verifiable Presentation.
// It performs the following checks as enabled:
//   - Parsing the presentation (supports both JWT and JSON-LD formats)
//   - Validating the presentation structure
//   - Verifying proof/signature (if WithVPVerifyProof is enabled)
//   - Checking expiration (if WithVPCheckExpiration is enabled)
//   - Validating embedded credentials (if WithVPValidateCredentials is enabled)
//   - Verifying audience claim (if WithVPVerifyAudience is enabled)
//   - Verifying nonce claim (if WithVPVerifyNonce is enabled)
//   - Verifying all embedded VCs using auth.Verify
//
// The function returns a VPVerifyResult containing the holder DID and
// aggregated permissions from all embedded VCs, or an error if verification fails.
func VerifyPresentation(ctx context.Context, presentation []byte, opts ...VPVerifyOpt) (*VPVerifyResult, error) {
	if len(presentation) == 0 {
		return nil, fmt.Errorf("presentation is empty")
	}

	verifyOpts := getVPVerifyOptions(opts...)

	// Build credential SDK options
	vpOpts := buildVPOptions(verifyOpts)

	// Parse presentation
	parsedVP, err := vp.ParsePresentation(presentation, vpOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}

	// Extract holder DID from presentation
	holderDID, err := extractHolderDID(parsedVP)
	if err != nil {
		return nil, fmt.Errorf("failed to extract holder DID: %w", err)
	}

	// Verify audience if requested
	if verifyOpts.isVerifyAudience {
		if err := verifyPresentationAudience(parsedVP, presentation, verifyOpts.expectedAudience); err != nil {
			return nil, err
		}
	}

	// Verify nonce if requested
	if verifyOpts.isVerifyNonce {
		if err := verifyPresentationNonce(parsedVP, presentation, verifyOpts.expectedNonce); err != nil {
			return nil, err
		}
	}

	// Extract and verify all embedded VCs
	allPermissions, err := verifyEmbeddedVCs(ctx, parsedVP, verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify embedded credentials: %w", err)
	}

	return &VPVerifyResult{
		HolderDID:      holderDID,
		AllPermissions: allPermissions,
	}, nil
}

// getVPVerifyOptions applies all VP verification options and returns the result.
func getVPVerifyOptions(opts ...VPVerifyOpt) *vpVerifyOptions {
	options := &vpVerifyOptions{
		didBaseURL:            "https://api.ndadid.vn/api/v1/did",
		verificationMethodKey: "key-1",
	}

	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	return options
}

// buildVPOptions converts auth SDK VP verification options to credential SDK options.
func buildVPOptions(opts *vpVerifyOptions) []vp.PresentationOpt {
	var vpOpts []vp.PresentationOpt

	if opts.didBaseURL != "" {
		vpOpts = append(vpOpts, vp.WithBaseURL(opts.didBaseURL))
	}

	if opts.verificationMethodKey != "" {
		vpOpts = append(vpOpts, vp.WithVerificationMethodKey(opts.verificationMethodKey))
	}

	if opts.isVerifyProof {
		vpOpts = append(vpOpts, vp.WithVerifyProof())
	}

	if opts.isCheckExpiration {
		vpOpts = append(vpOpts, vp.WithCheckExpiration())
	}

	if opts.isValidateVC {
		vpOpts = append(vpOpts, vp.WithVCValidation())
	}

	return vpOpts
}

// extractHolderDID extracts the holder DID from the presentation.
func extractHolderDID(parsedVP vp.Presentation) (string, error) {
	contents, err := parsedVP.GetContents()
	if err != nil {
		return "", fmt.Errorf("failed to get presentation contents: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(contents, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	holderRaw, ok := data["holder"]
	if !ok {
		return "", fmt.Errorf("holder field not found in presentation")
	}

	holderDID, ok := holderRaw.(string)
	if !ok || holderDID == "" {
		return "", fmt.Errorf("holder must be a non-empty string")
	}

	return holderDID, nil
}

// verifyPresentationAudience verifies that the presentation's audience matches expected value.
func verifyPresentationAudience(parsedVP vp.Presentation, rawPresentation []byte, expectedAudience string) error {
	contents, err := parsedVP.GetContents()
	if err != nil {
		return fmt.Errorf("failed to get presentation contents: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(contents, &data); err != nil {
		return fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	audienceRaw, ok := data["aud"]
	if !ok || audienceRaw == nil {
		jwtClaims, err := parseJWTPresentationClaims(rawPresentation)
		if err != nil {
			return err
		}

		if jwtClaims != nil {
			audienceRaw = jwtClaims["aud"]
		}

		if audienceRaw == nil {
			return fmt.Errorf("audience (aud) claim not found in presentation")
		}
	}

	audience, ok := audienceRaw.(string)
	if !ok || audience == "" {
		return fmt.Errorf("audience must be a non-empty string")
	}

	if audience != expectedAudience {
		return fmt.Errorf("audience mismatch: expected %s, got %s", expectedAudience, audience)
	}

	return nil
}

// verifyPresentationNonce verifies that the presentation's nonce matches expected value.
func verifyPresentationNonce(parsedVP vp.Presentation, rawPresentation []byte, expectedNonce string) error {
	contents, err := parsedVP.GetContents()
	if err != nil {
		return fmt.Errorf("failed to get presentation contents: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(contents, &data); err != nil {
		return fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	nonceRaw, ok := data["nonce"]
	if !ok || nonceRaw == nil {
		jwtClaims, err := parseJWTPresentationClaims(rawPresentation)
		if err != nil {
			return err
		}

		if jwtClaims != nil {
			nonceRaw = jwtClaims["nonce"]
		}

		if nonceRaw == nil {
			return fmt.Errorf("nonce claim not found in presentation")
		}
	}

	nonce, ok := nonceRaw.(string)
	if !ok || nonce == "" {
		return fmt.Errorf("nonce must be a non-empty string")
	}

	if nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch: expected %s, got %s", expectedNonce, nonce)
	}

	return nil
}

func parseJWTPresentationClaims(rawPresentation []byte) (map[string]interface{}, error) {
	parts := strings.Split(string(rawPresentation), ".")
	if len(parts) != 3 {
		// JSON presentations are allowed; no top-level JWT claims available.
		return nil, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt payload: %w", err)
	}

	claims := make(map[string]interface{})
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt payload: %w", err)
	}

	return claims, nil
}

// verifyEmbeddedVCs extracts and verifies all embedded VCs in the presentation.
// Returns aggregated permissions from all verified VCs.
func verifyEmbeddedVCs(ctx context.Context, parsedVP vp.Presentation, verifyOpts *vpVerifyOptions) ([]policy.Statement, error) {
	contents, err := parsedVP.GetContents()
	if err != nil {
		return nil, fmt.Errorf("failed to get presentation contents: %w", err)
	}

	var vpData map[string]interface{}
	if err := json.Unmarshal(contents, &vpData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	vcListRaw, ok := vpData["verifiableCredential"]
	if !ok || vcListRaw == nil {
		return nil, fmt.Errorf("no embedded credentials found in presentation")
	}

	vcList, ok := vcListRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("verifiableCredential must be an array")
	}

	if len(vcList) == 0 {
		return nil, fmt.Errorf("verifiableCredential array is empty")
	}

	// Extract VC tokens and verify each
	allStatements := make([]policy.Statement, 0)
	for i, vcItem := range vcList {
		var vcBytes []byte
		switch v := vcItem.(type) {
		case string:
			vcBytes = []byte(v)
		default:
			var marshalErr error
			vcBytes, marshalErr = json.Marshal(v)
			if marshalErr != nil {
				return nil, fmt.Errorf("failed to marshal embedded vc at index %d: %w", i, marshalErr)
			}
		}

		// Verify the VC using auth.Verify
		result, err := Verify(ctx, vcBytes,
			WithVerifyProof(),
			WithCheckExpiration(),
			WithVerifyPermissions(),
			WithDIDBaseURL(verifyOpts.didBaseURL),
			WithVerificationMethodKey(verifyOpts.verificationMethodKey),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to verify embedded vc at index %d: %w", i, err)
		}

		// TODO(phase 2): aggregate permissions from multiple VCs with conflict resolution
		// For now, collect all statements from verified VCs
		allStatements = append(allStatements, result.Permissions...)
	}

	return allStatements, nil
}
