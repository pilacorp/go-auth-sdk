package auth

import (
	"context"
	"testing"
)

// NOTE: This test is an integration-style helper that simply calls the real
// status API and logs the response. It uses the provided JWT as Authorization.
func TestHTTPStatusBuilder_CallAndLog(t *testing.T) {
	const issuerDID = "did:nda:testnet:0x123"

	// Use the given JWT as Authorization header (Bearer or raw depends on API config).
	const authToken = "Bearer <issuer-access-token>"

	builder := NewDefaultStatusBuilder(authToken)

	states, err := builder.CreateStatus(context.Background(), issuerDID)
	if err != nil {
		t.Fatalf("CreateStatus() error: %v", err)
	}

	t.Logf("status response: %+v", states)
}
