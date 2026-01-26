package vault

// SignMessageRequest represents the Vault API request for signing a message
type SignMessageRequest struct {
	Payload string `json:"payload"`
}

// SignMessageResponse represents the Vault API response for signing a message
type SignMessageResponse struct {
	Data struct {
		Signed string `json:"signature"`
	} `json:"data"`
}
