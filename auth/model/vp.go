// Package model defines shared data models for authorization credentials and presentations.
// It provides:
//   - AuthData and VPData: Input models for building VC-JWT credentials and VP-JWT presentations
//   - AuthResponse and VPResponse: Output models containing signed JWT tokens
//   - VerifyResult and VPVerifyResult: Normalized verification outputs with extracted identity data
package model

import "time"

// VPData holds the data needed to build a Verifiable Presentation.
// It contains references to VCs (as tokens or objects) and metadata.
type VPData struct {
	ID         string     // optional: presentation ID, SDK auto-generates UUID if empty
	HolderDID  string     // required: Holder DID (presenter)
	VCTokens   []string   // required: list of VC-JWT tokens to embed
	ValidFrom  *time.Time // optional: presentation validity start time
	ValidUntil *time.Time // optional: presentation validity end time
	Audience   string     // optional: the verifier the VP is meant for, signed into the "aud" claim
	Nonce      string     // optional: a value unique to this VP, signed into the "nonce" claim
}

// VPResponse represents the result of building a Verifiable Presentation.
type VPResponse struct {
	Token string `json:"token"`
}

// VPVerifyResult represents the result of presentation parsing.
// It contains the extracted holder DID and raw VC tokens for each embedded VC.
// Callers should parse and verify each VC token based on their own business logic.
type VPVerifyResult struct {
	HolderDID string        // The holder DID from the presentation
	VCs       []*VCResponse // Raw VC tokens extracted from the presentation
	// Nonce is the presentation's "nonce" claim, empty when it carries none or
	// is not a JWT. Callers can refuse a nonce they have already seen to make a
	// VP single use. Like HolderDID, trust it only with WithVPVerifyProof.
	Nonce string
}

// PresentationData represents the VP fields needed by the verifier.
type PresentationData struct {
	Holder               string   `json:"holder"`
	VerifiableCredential []string `json:"verifiableCredential"`
}
