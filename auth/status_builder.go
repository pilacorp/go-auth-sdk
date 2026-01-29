package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// StatusBuilder defines how credential status entries are created.
// Users can implement this interface to plug in custom status creation logic.
type StatusBuilder interface {
	// CreateStatus creates one or more credential status entries for the given issuer DID.
	CreateStatus(ctx context.Context, issuerDID string) ([]vc.Status, error)
}

// statusBuilder is the default implementation that calls an HTTP API
// to register credential status entries.
type statusBuilder struct {
	endpoint   string
	authToken  string
	httpClient *http.Client
}

// NewDefaultStatusBuilder creates a default StatusBuilder that calls
// the status registration API:
//
//	POST https://api.ndadid.vn/api/v1/credentials/status/register
//
// with body:
//
//	{ "issuerDid": "<issuer-did>" }
//
// The provided authToken will be sent in the Authorization header.
func NewDefaultStatusBuilder(authToken string) StatusBuilder {
	return &statusBuilder{
		endpoint:  "https://api.ndadid.vn/api/v1/credentials/status/register",
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CreateStatus implements StatusBuilder by calling the configured HTTP API.
func (p *statusBuilder) CreateStatus(ctx context.Context, issuerDID string) ([]vc.Status, error) {
	payload := statusRequest{
		IssuerDID: issuerDID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal status request payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if p.authToken != "" {
		req.Header.Set("Authorization", p.authToken)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call status provider API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status provider API returned non-success status: %s", resp.Status)
	}

	var res statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode status provider response: %w", err)
	}

	return []vc.Status{res.Data}, nil
}
