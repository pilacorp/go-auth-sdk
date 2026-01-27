package ecdsa

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/signer"
)

func TestNewProviderPriv(t *testing.T) {
	p := NewPrivSigner()
	if p == nil {
		t.Fatal("NewPrivSigner() returned nil")
	}

	// Verify it implements the Provider interface
	var _ signer.Signer = p
}

func TestProviderPriv_Sign(t *testing.T) {
	// Generate a valid private key for testing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	// Create a 32-byte payload (crypto.Sign requires 32-byte hash)
	payload := make([]byte, 32)
	copy(payload, []byte("test payload 32 bytes long!!"))

	tests := []struct {
		name    string
		payload []byte
		opts    []signer.SignOption
		wantErr bool
	}{
		{
			name:    "successful sign with valid private key",
			payload: payload,
			opts:    []signer.SignOption{signer.WithPrivateKey(privateKeyBytes)},
			wantErr: false,
		},
		{
			name:    "error with invalid private key",
			payload: payload,
			opts:    []signer.SignOption{signer.WithPrivateKey([]byte("invalid key"))},
			wantErr: true,
		},
		{
			name:    "error with missing private key",
			payload: payload,
			opts:    []signer.SignOption{},
			wantErr: true,
		},
		{
			name:    "error with non-32-byte payload",
			payload: []byte("short payload"),
			opts:    []signer.SignOption{signer.WithPrivateKey(privateKeyBytes)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPrivSigner()
			ctx := context.Background()

			sig, err := p.Sign(ctx, tt.payload, tt.opts...)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Sign() expected error but got none")
				}
				if sig != nil {
					t.Errorf("Sign() expected nil signature on error, got %v", sig)
				}
			} else {
				if err != nil {
					t.Errorf("Sign() unexpected error: %v", err)
				}
				if len(sig) != 64 {
					t.Errorf("Sign() signature length = %d, want 64", len(sig))
				}
			}
		})
	}
}

func TestPrivSigner_GetAddress(t *testing.T) {
	// Generate a valid private key for testing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	p := NewPrivSigner().(*privSigner)

	addr, err := p.GetAddress(signer.WithPrivateKey(privateKeyBytes))
	if err != nil {
		t.Fatalf("GetAddress() unexpected error: %v", err)
	}
	if addr != expectedAddr {
		t.Errorf("GetAddress() = %v, want %v", addr, expectedAddr)
	}
}

func TestPrivSigner_GetAddress_MissingPrivateKey(t *testing.T) {
	p := NewPrivSigner().(*privSigner)

	addr, err := p.GetAddress()
	if err == nil {
		t.Fatalf("GetAddress() expected error but got nil")
	}
	if addr != "" {
		t.Errorf("GetAddress() = %v, want empty string on error", addr)
	}
}
