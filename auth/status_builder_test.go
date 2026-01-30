package auth

import (
	"context"
	"testing"
)

// TestStatusBuilder_CallAndLog is an integration test that calls the real status API.
// It will be skipped if a valid auth token is not provided.
// To run this test, set a valid token in the environment or update the authToken constant.
func TestStatusBuilder_CallAndLog(t *testing.T) {
	const issuerDID = "did:nda:testnet:0x123"

	// Use the given JWT as Authorization header (Bearer or raw depends on API config).
	// Update this with a valid token to run the integration test.
	const authToken = "Bearer <issuer-access-token>"

	// Skip test if token is placeholder
	if authToken == "Bearer <issuer-access-token>" {
		t.Skip("Skipping integration test: valid auth token not provided")
	}

	builder := NewStatusBuilder(authToken, "https://api.ndadid.vn/api/v1/credentials/status/register")

	states, err := builder.CreateStatus(context.Background(), issuerDID)
	if err != nil {
		t.Fatalf("CreateStatus() error: %v", err)
	}

	if len(states) == 0 {
		t.Error("CreateStatus() returned empty status list")
	}

	t.Logf("status response: %+v", states)
}
