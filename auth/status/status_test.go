package status

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestStatusBuilder_CreateStatus_TypeValidation(t *testing.T) {
	tests := []struct {
		name       string
		responseVC string
		wantErr    string
		wantType   string
	}{
		{
			name: "entry with a type is returned",
			responseVC: `{"data":{"id":"https://example.com/status/0#0","type":"BitstringStatusListEntry",
				"statusPurpose":"revocation","statusListIndex":"0",
				"statusListCredential":"https://example.com/status/0"}}`,
			wantType: "BitstringStatusListEntry",
		},
		{
			name: "entry without a type is rejected here, not at credential build time",
			responseVC: `{"data":{"id":"https://example.com/status/0#0",
				"statusPurpose":"revocation","statusListIndex":"0"}}`,
			wantErr: "status provider API returned an entry without a type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.responseVC))
			}))
			defer server.Close()

			builder := NewStatusBuilder("Bearer test-token", server.URL)

			statuses, err := builder.CreateStatus(context.Background(), "did:nda:testnet:0x123")

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("CreateStatus() error = nil, want %q", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("CreateStatus() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("CreateStatus() unexpected error: %v", err)
			}
			if len(statuses) != 1 {
				t.Fatalf("CreateStatus() returned %d statuses, want 1", len(statuses))
			}
			if statuses[0].Type != tt.wantType {
				t.Fatalf("status type = %q, want %q", statuses[0].Type, tt.wantType)
			}
		})
	}
}
