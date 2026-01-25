package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Constants for HTTP settings
const (
	contentTypeJSON   = "application/json"
	acceptHeader      = "*/*"
	defaultTimeout    = 10 * time.Second
	defaultMaxRetries = 3
)

// Vault holds the configuration for the Vault endpoint
type Vault struct {
	Address    string // Vault server address (e.g., http://109.237.70.93:8200)
	Token      string // Vault authentication token
	MaxRetries int    // Maximum number of retries for HTTP requests
	httpClient *http.Client
}

// NewVault initializes a new Vault instance with the specified address, token, and optional max retries
func NewVault(address, token string, maxRetries ...int) *Vault {
	retries := defaultMaxRetries
	if len(maxRetries) > 0 && maxRetries[0] >= 0 {
		retries = maxRetries[0]
	}

	return &Vault{
		Address:    address,
		Token:      token,
		MaxRetries: retries,
		httpClient: newHTTPClient(),
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
	}
}

// applyCommonHeaders applies common HTTP headers to the request
func (v *Vault) applyCommonHeaders(req *http.Request, bodyLen int) {
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("X-Vault-Token", v.Token)
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("Host", v.Address)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", bodyLen))
}

// decodeHexSignature safely decodes a hex string signature, handling the "0x" prefix
// Returns an error if the string is too short or if decoding fails
func decodeHexSignature(signedHex string) ([]byte, error) {
	if len(signedHex) < 2 {
		return nil, fmt.Errorf("signed hex string too short: expected at least 2 characters, got %d", len(signedHex))
	}

	// Remove "0x" prefix if present
	if signedHex[0:2] == "0x" {
		signedHex = signedHex[2:]
	}

	if len(signedHex) == 0 {
		return nil, fmt.Errorf("signed hex string is empty after removing prefix")
	}

	signatureBytes, err := hex.DecodeString(signedHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	if len(signatureBytes) < 64 {
		return nil, fmt.Errorf("signature too short: expected at least 64 bytes, got %d", len(signatureBytes))
	}

	return signatureBytes, nil
}

// SignMessage signs a message using the Vault ethsign endpoint and returns the signed message
//
// - payload: 32 bytes hash of the message
//
// - address: hexa string with 0x prefix of the address
//
// - return: 64 bytes signature
func (v *Vault) SignMessage(ctx context.Context, payload []byte, address string) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload must be 32 bytes")
	}

	if len(address) != 42 {
		return nil, fmt.Errorf("address must be 42 characters")
	}

	// Create request payload
	reqBody := &SignMessageRequest{Payload: "0x" + hex.EncodeToString(payload)}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Construct endpoint URL
	endpoint := v.Address + "/v1/secp/accounts/" + address + "/signRaw"

	for attempt := 0; attempt <= v.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(jsonBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		v.applyCommonHeaders(req, len(jsonBody))

		resp, err := v.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		// Read response body for error details
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) && attempt < v.MaxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d, response body: %s", resp.StatusCode, string(body))
		}

		var response SignMessageResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w, response body: %s", err, string(body))
		}

		signatureBytes, err := decodeHexSignature(response.Data.Signed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature: %w, response body: %s", err, string(body))
		}

		return signatureBytes[:64], nil
	}

	return nil, fmt.Errorf("max retries exceeded")
}
