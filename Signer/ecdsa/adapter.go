// Package ecdsa provides an implementation of the provider interface that uses a private key for signing.
package ecdsa

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	signer "github.com/pilacorp/go-auth-sdk/signer"
)

// privSigner is the provider implementation that uses a private key for signing.
type privSigner struct{}

// NewPrivSigner creates a new privSigner instance.
func NewPrivSigner() signer.Signer {
	return &privSigner{}
}

// Sign signs the payload using the private key
func (p *privSigner) Sign(ctx context.Context, payload []byte, opts ...signer.SignOption) ([]byte, error) {
	options := &signer.SignOptions{}
	for _, opt := range opts {
		opt(options)
	}

	privateKey, err := crypto.ToECDSA(options.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct private key from retrieved hex: %w", err)
	}

	sig, err := crypto.Sign(payload, privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return sig[:64], nil
}
