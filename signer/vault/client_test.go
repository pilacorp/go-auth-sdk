package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewVault(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		token       string
		maxRetries  []int
		wantRetries int
	}{
		{
			name:        "default max retries",
			address:     "http://localhost:8200",
			token:       "test-token",
			maxRetries:  []int{},
			wantRetries: defaultMaxRetries,
		},
		{
			name:        "custom max retries",
			address:     "http://localhost:8200",
			token:       "test-token",
			maxRetries:  []int{5},
			wantRetries: 5,
		},
		{
			name:        "zero max retries",
			address:     "http://localhost:8200",
			token:       "test-token",
			maxRetries:  []int{0},
			wantRetries: 0,
		},
		{
			name:        "negative max retries ignored",
			address:     "http://localhost:8200",
			token:       "test-token",
			maxRetries:  []int{-1},
			wantRetries: defaultMaxRetries,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVault(tt.address, tt.token, tt.maxRetries...)
			if v == nil {
				t.Fatal("NewVault() returned nil")
			}
			if v.Address != tt.address {
				t.Errorf("Address = %v, want %v", v.Address, tt.address)
			}
			if v.Token != tt.token {
				t.Errorf("Token = %v, want %v", v.Token, tt.token)
			}
			if v.MaxRetries != tt.wantRetries {
				t.Errorf("MaxRetries = %v, want %v", v.MaxRetries, tt.wantRetries)
			}
			if v.httpClient == nil {
				t.Error("httpClient is nil")
			}
		})
	}
}

func TestVault_SignMessage_Success(t *testing.T) {
	// Create a 32-byte payload
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))
	address := "0x1234567890123456789012345678901234567890"

	// Create expected signature (64 bytes)
	expectedSig := make([]byte, 64)
	for i := range expectedSig {
		expectedSig[i] = byte(i)
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodPost {
			t.Errorf("Method = %v, want POST", r.Method)
		}

		// Verify request path
		expectedPath := "/v1/secp/accounts/" + address + "/signRaw"
		if r.URL.Path != expectedPath {
			t.Errorf("Path = %v, want %v", r.URL.Path, expectedPath)
		}

		// Verify headers
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Errorf("X-Vault-Token = %v, want test-token", r.Header.Get("X-Vault-Token"))
		}

		// Verify request body
		var req SignMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}

		expectedPayload := "0x" + hex.EncodeToString(payload)
		if req.Payload != expectedPayload {
			t.Errorf("Payload = %v, want %v", req.Payload, expectedPayload)
		}

		// Create response
		response := SignMessageResponse{
			Data: struct {
				Signed string `json:"signature"`
			}{
				Signed: "0x" + hex.EncodeToString(expectedSig),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create Vault client pointing to mock server
	v := NewVault(server.URL, "test-token", 3)
	ctx := context.Background()

	sig, err := v.SignMessage(ctx, payload, address)

	if err != nil {
		t.Fatalf("SignMessage() unexpected error: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("SignMessage() signature length = %d, want 64", len(sig))
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Errorf("SignMessage() signature = %v, want %v", sig, expectedSig)
	}
}

func TestVault_SignMessage_InvalidPayload(t *testing.T) {
	address := "0x1234567890123456789012345678901234567890"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Server should not be called with invalid payload")
	}))
	defer server.Close()

	v := NewVault(server.URL, "test-token", 3)
	ctx := context.Background()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "payload too short",
			payload: []byte("short"),
		},
		{
			name:    "payload too long",
			payload: make([]byte, 64),
		},
		{
			name:    "nil payload",
			payload: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := v.SignMessage(ctx, tt.payload, address)

			if err == nil {
				t.Error("SignMessage() expected error but got none")
			}
			if sig != nil {
				t.Errorf("SignMessage() expected nil signature on error, got %v", sig)
			}
			if err.Error() != "payload must be 32 bytes" {
				t.Errorf("SignMessage() error = %v, want 'payload must be 32 bytes'", err)
			}
		})
	}
}

func TestVault_SignMessage_InvalidAddress(t *testing.T) {
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Server should not be called with invalid address")
	}))
	defer server.Close()

	v := NewVault(server.URL, "test-token", 3)
	ctx := context.Background()

	tests := []struct {
		name    string
		address string
	}{
		{
			name:    "address too short",
			address: "0x123",
		},
		{
			name:    "address too long",
			address: "0x123456789012345678901234567890123456789012",
		},
		{
			name:    "empty address",
			address: "",
		},
		{
			name:    "address without 0x prefix",
			address: "1234567890123456789012345678901234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := v.SignMessage(ctx, payload, tt.address)

			if err == nil {
				t.Error("SignMessage() expected error but got none")
			}
			if sig != nil {
				t.Errorf("SignMessage() expected nil signature on error, got %v", sig)
			}
			if err.Error() != "address must be 42 characters" {
				t.Errorf("SignMessage() error = %v, want 'address must be 42 characters'", err)
			}
		})
	}
}

func TestVault_SignMessage_ServerError(t *testing.T) {
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))
	address := "0x1234567890123456789012345678901234567890"

	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectedErrMsg string
	}{
		{
			name:           "server error 500",
			statusCode:     http.StatusInternalServerError,
			responseBody:   `{"error": "internal server error"}`,
			expectedErrMsg: "unexpected status code: 500",
		},
		{
			name:           "server error 400",
			statusCode:     http.StatusBadRequest,
			responseBody:   `{"error": "bad request"}`,
			expectedErrMsg: "unexpected status code: 400",
		},
		{
			name:           "server error 401",
			statusCode:     http.StatusUnauthorized,
			responseBody:   `{"error": "unauthorized"}`,
			expectedErrMsg: "unexpected status code: 401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			v := NewVault(server.URL, "test-token", 0) // No retries
			ctx := context.Background()

			sig, err := v.SignMessage(ctx, payload, address)

			if err == nil {
				t.Error("SignMessage() expected error but got none")
			}
			if sig != nil {
				t.Errorf("SignMessage() expected nil signature on error, got %v", sig)
			}
			if err.Error()[:len(tt.expectedErrMsg)] != tt.expectedErrMsg {
				t.Errorf("SignMessage() error = %v, want prefix %v", err, tt.expectedErrMsg)
			}
		})
	}
}
