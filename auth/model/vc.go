// Package model defines shared data models for authorization credentials and presentations.
// It provides:
//   - AuthData and VPData: Input models for building VC-JWT credentials and VP-JWT presentations
//   - AuthResponse and VPResponse: Output models containing signed JWT tokens
//   - VerifyResult and VPVerifyResult: Normalized verification outputs with extracted identity data
package model

import (
	"encoding/json"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// VCData holds the credential-specific data.
type VCData struct {
	ID               string
	IssuerDID        string
	HolderDID        string
	Policy           policy.Policy
	CustomFields     map[string]any
	CredentialStatus []vc.Status
	ValidFrom        *time.Time
	ValidUntil       *time.Time
}

// VCResponse represents the result of building a credential.
type VCResponse struct {
	Token string `json:"token"`
}

// VCVerifyResult represents the normalized result of credential verification.
// It contains the extracted issuer DID, holder DID, and validated permissions
// from a successfully verified credential.
type VCVerifyResult struct {
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

// CredentialData represents the structure of credential data (without proof).
type CredentialData struct {
	Issuer            string            `json:"issuer"`
	CredentialSchema  credentialSchema  `json:"credentialSchema"`
	CredentialSubject credentialSubject `json:"credentialSubject"`
}
