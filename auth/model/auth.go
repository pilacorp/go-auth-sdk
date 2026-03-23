// Package model defines shared data models for authorization credentials and presentations.
// It provides:
//   - AuthData and VPData: Input models for building VC-JWT credentials and VP-JWT presentations
//   - AuthResponse and VPResponse: Output models containing signed JWT tokens
//   - VerifyResult and VPVerifyResult: Normalized verification outputs with extracted identity data
package model

import (
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
