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
}

// VPResponse represents the result of building a Verifiable Presentation.
type VPResponse struct {
	Token string `json:"token"`
}

// VPVerifyResult represents the result of presentation parsing.
// It contains the extracted holder DID and raw VC tokens for each embedded VC.
// Callers should parse and verify each VC token based on their own business logic.
type VPVerifyResult struct {
	HolderDID string          // The holder DID from the presentation
	VCs       []*AuthResponse // Raw VC tokens extracted from the presentation
}
