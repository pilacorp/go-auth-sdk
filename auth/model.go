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
	SchemaID         string
	HolderDID        string
	Policy           policy.Policy
	ValidFrom        *time.Time
	ValidUntil       *time.Time
	CredentialStatus []vc.Status
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
