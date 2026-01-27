package auth

import (
	"encoding/json"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
)

// AuthData holds the authentication-specific data.
type AuthData struct {
	HolderDID  string
	Policy     policy.Policy
	ValidFrom  *time.Time
	ValidUntil *time.Time
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

// credentialData represents the structure of credential data (without proof).
type credentialData struct {
	Issuer            string            `json:"issuer"`
	CredentialSubject credentialSubject `json:"credentialSubject"`
}
