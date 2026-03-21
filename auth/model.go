package auth

import (
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// statusRequest represents the status registration API request body
type statusRequest struct {
	IssuerDID string `json:"issuerDid"`
}

// statusResponse represents the status registration API response
type statusResponse struct {
	Data vc.Status `json:"data"`
}
