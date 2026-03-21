package verifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-auth-sdk/auth/model"
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
}

// presentationData represents the VP fields needed by the verifier.
type presentationData struct {
	Holder               string   `json:"holder"`
	VerifiableCredential []string `json:"verifiableCredential"`
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

// VerifyPresentation parses a Verifiable Presentation and extracts the holder DID
// and raw VC tokens. It performs VP-level verification (proof and expiration)
// if enabled via options.
//
// Callers should parse and verify each VC token based on their own business logic.
//
// The function returns a VPVerifyResult containing the holder DID and
// raw VC tokens, or an error if verification fails.
func VerifyPresentation(ctx context.Context, presentation []byte, opts ...VPVerifyOpt) (*model.VPVerifyResult, error) {
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

	var vpData presentationData
	if err := json.Unmarshal(vpContents, &vpData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	// Extract holder DID from cached contents
	holderDID, err := extractHolderDIDFromData(vpData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract holder DID: %w", err)
	}

	// Extract all embedded VC tokens
	vcTokens, err := extractVCTokens(vpData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract VC tokens: %w", err)
	}

	return &model.VPVerifyResult{
		HolderDID: holderDID,
		VCs:       vcTokens,
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

	return vpOpts
}

// extractHolderDIDFromData extracts the holder DID from the unmarshaled VP data.
func extractHolderDIDFromData(vpData presentationData) (string, error) {
	if vpData.Holder == "" {
		return "", fmt.Errorf("holder must be a non-empty string")
	}

	return vpData.Holder, nil
}

// extractVCTokens extracts all embedded VC tokens from the VP data.
// Each VC is returned as an AuthResponse containing the raw JWT token.
func extractVCTokens(vpData presentationData) ([]*model.AuthResponse, error) {
	if vpData.VerifiableCredential == nil {
		return nil, fmt.Errorf("no embedded credentials found in presentation")
	}

	if len(vpData.VerifiableCredential) == 0 {
		return nil, fmt.Errorf("verifiableCredential array is empty")
	}

	tokens := make([]*model.AuthResponse, 0, len(vpData.VerifiableCredential))
	for _, token := range vpData.VerifiableCredential {
		tokens = append(tokens, &model.AuthResponse{Token: token})
	}

	return tokens, nil
}
