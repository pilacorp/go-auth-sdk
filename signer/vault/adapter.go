// Package vault provides an implementation of the signer interface that uses Vault for signing.
package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/pilacorp/go-auth-sdk/signer"
)

// vaultSigner is the signer implementation that uses Vault for signing.
type vaultSigner struct {
	vault *Vault
}

// NewVaultSigner creates a new vaultSigner instance.
// It connects to Vault using the provided address and token and optional max retries.
func NewVaultSigner(address, token string, maxRetries ...int) signer.Signer {
	return &vaultSigner{
		vault: NewVault(address, token, maxRetries...),
	}
}

// Sign signs the payload using Vault.
func (v *vaultSigner) Sign(ctx context.Context, payload []byte, opts ...signer.SignOption) ([]byte, error) {
	options := &signer.SignOptions{}
	for _, opt := range opts {
		opt(options)
	}

	return v.vault.SignMessage(ctx, payload, options.SignerAddress)
}

// GetAddress gets the address of the signer.
func (v *vaultSigner) GetAddress(opts ...signer.SignOption) (string, error) {
	options := &signer.SignOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if options.SignerAddress == "" {
		return "", fmt.Errorf("signer address is required for Vault signer")
	}

	return strings.ToLower(options.SignerAddress), nil
}
