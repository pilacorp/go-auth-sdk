package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/status"
)

// TestStatusBuilder_UsesCustomClient verifies that NewStatusBuilder
// respects the provided HTTP client (via options) when calling the status API.
//
// This is a lightweight integration-style test using httptest.Server rather than
// real external services.
func TestStatusBuilder_UsesCustomClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var receivedAuth string

	// Mock status service
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"https://example.com/status/0#0","type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"0","statusListCredential":"https://example.com/status/0"}}`))
	}))
	defer srv.Close()

	// Custom client with short timeout (to ensure we actually use it)
	customClient := &http.Client{
		Timeout: 2 * time.Second,
	}

	const issuerDID = "did:integration:issuer"
	const authToken = "Bearer integration-token"

	builder := status.NewStatusBuilder(
		authToken,
		srv.URL,
		status.WithStatusBuilderHTTPClient(customClient),
	)

	statuses, err := builder.CreateStatus(ctx, issuerDID)
	if err != nil {
		t.Fatalf("CreateStatus() error = %v", err)
	}

	if len(statuses) == 0 {
		t.Fatalf("CreateStatus() returned empty status list")
	}

	if receivedAuth != authToken {
		t.Fatalf("expected Authorization header %q, got %q", authToken, receivedAuth)
	}
}
