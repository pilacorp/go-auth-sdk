package vault

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pilacorp/go-auth-sdk/signer"
)

func TestNewVaultSigner(t *testing.T) {
	s := NewVaultSigner("http://localhost:8200", "test-token")
	if s == nil {
		t.Fatal("NewVaultSigner() returned nil")
	}

	// Verify it implements the Signer interface
	var _ signer.Signer = s
}
func TestVaultSigner_Sign_Success(t *testing.T) {
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))
	address := "0x1234567890123456789012345678901234567890"

	expectedSig := make([]byte, 64)
	for i := range expectedSig {
		expectedSig[i] = byte(i)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request path contains the address
		expectedPath := "/v1/secp/accounts/" + address + "/signRaw"
		if r.URL.Path != expectedPath {
			t.Errorf("Path = %v, want %v", r.URL.Path, expectedPath)
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

	s := NewVaultSigner(server.URL, "test-token")
	ctx := context.Background()

	sig, err := s.Sign(ctx, payload, signer.WithSignerAddress(address))

	if err != nil {
		t.Fatalf("Sign() unexpected error: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("Sign() signature length = %d, want 64", len(sig))
	}
}

func TestVaultSigner_Sign_MissingAddress(t *testing.T) {
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Server should not be called without address")
	}))
	defer server.Close()

	s := NewVaultSigner(server.URL, "test-token")
	ctx := context.Background()

	sig, err := s.Sign(ctx, payload) // No address provided

	if err == nil {
		t.Error("Sign() expected error but got none")
	}
	if sig != nil {
		t.Errorf("Sign() expected nil signature on error, got %v", sig)
	}
	// The error should be from Vault.SignMessage about invalid address
	if err.Error() != "address must be 42 characters" {
		t.Errorf("Sign() error = %v, want 'address must be 42 characters'", err)
	}
}

func TestVaultSigner_Sign_InvalidPayload(t *testing.T) {
	address := "0x1234567890123456789012345678901234567890"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Server should not be called with invalid payload")
	}))
	defer server.Close()

	s := NewVaultSigner(server.URL, "test-token")
	ctx := context.Background()

	sig, err := s.Sign(ctx, []byte("short"), signer.WithSignerAddress(address))

	if err == nil {
		t.Error("Sign() expected error but got none")
	}
	if sig != nil {
		t.Errorf("Sign() expected nil signature on error, got %v", sig)
	}
	if err.Error() != "payload must be 32 bytes" {
		t.Errorf("Sign() error = %v, want 'payload must be 32 bytes'", err)
	}
}

func TestVaultSigner_Sign_ServerError(t *testing.T) {
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))
	address := "0x1234567890123456789012345678901234567890"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	s := NewVaultSigner(server.URL, "test-token", 0) // No retries
	ctx := context.Background()

	sig, err := s.Sign(ctx, payload, signer.WithSignerAddress(address))

	if err == nil {
		t.Error("Sign() expected error but got none")
	}
	if sig != nil {
		t.Errorf("Sign() expected nil signature on error, got %v", sig)
	}
	if err.Error()[:len("unexpected status code")] != "unexpected status code" {
		t.Errorf("Sign() error = %v, want prefix 'unexpected status code'", err)
	}
}

func TestVaultSigner_Sign_WithPrivateKey(t *testing.T) {
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))
	address := "0x1234567890123456789012345678901234567890"

	expectedSig := make([]byte, 64)
	for i := range expectedSig {
		expectedSig[i] = byte(i)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	s := NewVaultSigner(server.URL, "test-token")
	ctx := context.Background()

	// PrivateKey should be ignored by the vault signer, but shouldn't cause errors
	privateKey := []byte("some-private-key")

	sig, err := s.Sign(ctx, payload,
		signer.WithSignerAddress(address),
		signer.WithPrivateKey(privateKey),
	)

	if err != nil {
		t.Fatalf("Sign() unexpected error: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("Sign() signature length = %d, want 64", len(sig))
	}
}
