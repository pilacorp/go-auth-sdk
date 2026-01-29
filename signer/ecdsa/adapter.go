// Package ecdsa provides an implementation of the provider interface that uses a private key for signing.
package ecdsa

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/signer"
)

// privSigner is the provider implementation that uses a private key for signing.
type privSigner struct {
	defaultPrivateKey []byte
}

// NewPrivSigner creates a new privSigner instance with a private key embedded in the struct.
// The private key can still be overridden via signer.WithPrivateKey() option when calling Sign().
// Input nil if you want to use the private key from the signer.
func NewPrivSigner(privateKey []byte) signer.Signer {
	return &privSigner{
		defaultPrivateKey: privateKey,
	}
}

// Sign signs the payload using the private key.
// Private key priority: opts.PrivateKey (if provided) > p.privateKey (struct field).
// At least one must be provided, otherwise returns an error.
func (p *privSigner) Sign(ctx context.Context, payload []byte, opts ...signer.SignOption) ([]byte, error) {
	options := &signer.SignOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Determine which private key to use: opts take precedence over struct field
	var privateKeyBytes []byte
	if options.PrivateKey != nil {
		privateKeyBytes = options.PrivateKey
	} else if p.defaultPrivateKey != nil {
		privateKeyBytes = p.defaultPrivateKey
	} else {
		return nil, fmt.Errorf("private key is not provided: neither in options nor in signer struct")
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	sig, err := crypto.Sign(payload, privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return sig[:64], nil
}
