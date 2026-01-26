package auth

import (
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
