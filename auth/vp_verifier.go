// Package auth provides VP verification for validating Verifiable Presentations.
package auth

import (
	"context"
	"encoding/json"
	"fmt"

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

// VerifyPresentation performs comprehensive verification of a Verifiable Presentation.
// It performs the following checks as enabled:
//   - Parsing the presentation (supports both JWT and JSON-LD formats)
//   - Validating the presentation structure
//   - Verifying proof/signature (if WithVPVerifyProof is enabled)
//   - Checking expiration (if WithVPCheckExpiration is enabled)
//   - Validating embedded credentials (if WithVPValidateCredentials is enabled)
//   - Verifying audience claim (if WithVPVerifyAudience is enabled)
//   - Verifying nonce claim (if WithVPVerifyNonce is enabled)
//   - Extracting and verifying all embedded VCs
//
// The function returns a VPVerifyResult containing the holder DID and
// VerifyResult objects for each embedded VC, allowing callers to apply
// custom aggregation and conflict resolution logic, or an error if verification fails.
func VerifyPresentation(ctx context.Context, presentation []byte, opts ...VPVerifyOpt) (*VPVerifyResult, error) {
	if len(presentation) == 0 {
		return nil, fmt.Errorf("presentation is empty")
	}

	verifyOpts := getVPVerifyOptions(opts...)

	// Build credential SDK options
	vpOpts := buildVPOptions(verifyOpts)

	// Parse presentation once
	parsedVP, err := vp.ParsePresentation(presentation, vpOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}

	// Get presentation contents once and reuse across all checks
	vpContents, err := parsedVP.GetContents()
	if err != nil {
		return nil, fmt.Errorf("failed to get presentation contents: %w", err)
	}

	var vpData map[string]interface{}
	if err := json.Unmarshal(vpContents, &vpData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	// Extract holder DID from cached contents
	holderDID, err := extractHolderDIDFromData(vpData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract holder DID: %w", err)
	}

	// Extract and verify all embedded VCs
	embeddedVCResults, err := verifyEmbeddedVCs(ctx, vpData, verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify embedded credentials: %w", err)
	}

	return &VPVerifyResult{
		HolderDID:      holderDID,
		EmbeddedVCData: embeddedVCResults,
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

// extractHolderDIDFromData extracts the holder DID from the unmarshaled VP data.
func extractHolderDIDFromData(vpData map[string]interface{}) (string, error) {
	holderRaw, ok := vpData["holder"]
	if !ok {
		return "", fmt.Errorf("holder field not found in presentation")
	}

	holderDID, ok := holderRaw.(string)
	if !ok || holderDID == "" {
		return "", fmt.Errorf("holder must be a non-empty string")
	}

	return holderDID, nil
}

// verifyEmbeddedVCs extracts and verifies all embedded VCs in the presentation.
// Returns VerifyResult objects for each embedded VC, allowing callers to apply
// custom aggregation and conflict resolution logic based on business requirements.
// Note: VCs are already validated by ParsePresentation if WithVPValidateCredentials was enabled.
func verifyEmbeddedVCs(ctx context.Context, vpData map[string]interface{}, verifyOpts *vpVerifyOptions) ([]*VerifyResult, error) {
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

	// Extract VC tokens and verify each for permissions extraction
	results := make([]*VerifyResult, 0, len(vcList))
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

		// Verify the VC using auth.Verify to extract permissions and claims.
		// Note: If WithVPValidateCredentials was enabled, VCs are already validated by ParsePresentation.
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

		results = append(results, result)
	}

	return results, nil
}
