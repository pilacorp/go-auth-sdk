package auth

import (
	"encoding/json"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// AuthData holds the authentication-specific data.
type AuthData struct {
	ID               string
	IssuerDID        string
	HolderDID        string
	Policy           policy.Policy
	CredentialStatus []vc.Status
	ValidFrom        *time.Time
	ValidUntil       *time.Time
}

// AuthResponse represents the result of building an authentication.
type AuthResponse struct {
	Token string `json:"token"`
}

// VerifyResult represents the normalized result of credential verification.
// It contains the extracted issuer DID, holder DID, and validated permissions
// from a successfully verified credential.
type VerifyResult struct {
	IssuerDID   string             // The issuer DID from the credential
	HolderDID   string             // The holder DID from credentialSubject.id
	Permissions []policy.Statement // The extracted and validated permissions
}

// credentialSubject represents a credentialSubject object with id and optional permissions.
type credentialSubject struct {
	ID          string          `json:"id"`
	Permissions json.RawMessage `json:"permissions,omitempty"`
}

// credentialSchema represents the structure of credential schema.
type credentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// credentialData represents the structure of credential data (without proof).
type credentialData struct {
	Issuer            string            `json:"issuer"`
	CredentialSchema  credentialSchema  `json:"credentialSchema"`
	CredentialSubject credentialSubject `json:"credentialSubject"`
}

// statusRequest represents the status registration API request body
type statusRequest struct {
	IssuerDID string `json:"issuerDid"`
}

// statusResponse represents the status registration API response
type statusResponse struct {
	Data vc.Status `json:"data"`
}

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
	HolderDID string   // The holder DID from the presentation
	VC        []*AuthResponse // Raw VC tokens extracted from the presentation
}
