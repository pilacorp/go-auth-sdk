// Package signer provides a signer interface for signing operations.
// It supports both local private key and Vault signers.
package signer

import (
	"context"
)

// SignOptions represents the options for signing a payload.
type SignOptions struct {
	SignerAddress string
	PrivateKey    []byte
	CustomData    map[string]any
}

type SignOption func(*SignOptions)

// Signer defines the signing capability used by the auth service.
// Sign should take an arbitrary payload and return the signed token bytes.
type Signer interface {
	Sign(ctx context.Context, payload []byte, opts ...SignOption) ([]byte, error)
	GetAddress(opts ...SignOption) (string, error)
}

// WithSignerAddress sets the signer address for the signing operation.
func WithSignerAddress(address string) SignOption {
	return func(o *SignOptions) {
		o.SignerAddress = address
	}
}

// WithCustomData sets the custom data for the signing operation.
func WithCustomData(data map[string]any) SignOption {
	return func(o *SignOptions) {
		o.CustomData = data
	}
}

// WithPrivateKey sets the private key for the signing operation.
func WithPrivateKey(privateKey []byte) SignOption {
	return func(o *SignOptions) {
		o.PrivateKey = privateKey
	}
}
