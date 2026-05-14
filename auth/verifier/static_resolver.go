package verifier

import (
	"context"
	"fmt"
	"strings"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// StaticResolver returns a synthetic DID Document with one
// EcdsaSecp256k1VerificationKey2019 VM. For tests/examples only.
type StaticResolver struct {
	publicKeyHex string
	keyFragment  string
}

// StaticResolverOption configures a StaticResolver.
type StaticResolverOption func(*StaticResolver)

// WithStaticKeyFragment overrides the default key fragment ("key-1").
func WithStaticKeyFragment(fragment string) StaticResolverOption {
	return func(r *StaticResolver) {
		r.keyFragment = strings.TrimPrefix(fragment, "#")
	}
}

// NewStaticResolver builds a StaticResolver for the given secp256k1 public
// key (hex, optional "0x" prefix).
func NewStaticResolver(publicKeyHex string, opts ...StaticResolverOption) (*StaticResolver, error) {
	if publicKeyHex == "" {
		return nil, fmt.Errorf("public key is empty")
	}

	r := &StaticResolver{
		publicKeyHex: publicKeyHex,
		keyFragment:  "key-1",
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	if r.keyFragment == "" {
		return nil, fmt.Errorf("key fragment is empty")
	}
	return r, nil
}

// ResolveDocument implements verificationmethod.ResolverProvider.
func (r *StaticResolver) ResolveDocument(_ context.Context, did string) (*verificationmethod.DIDDocument, error) {
	if did == "" {
		return nil, fmt.Errorf("did is empty")
	}

	vmID := did + "#" + r.keyFragment
	pubHex := r.publicKeyHex
	if !strings.HasPrefix(pubHex, "0x") {
		pubHex = "0x" + pubHex
	}

	return &verificationmethod.DIDDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      did,
		VerificationMethod: []verificationmethod.VerificationMethodEntry{
			{
				ID:           vmID,
				Type:         "EcdsaSecp256k1VerificationKey2019",
				Controller:   did,
				PublicKeyHex: pubHex,
			},
		},
		Authentication:      []string{vmID},
		AssertionMethod:     []string{vmID},
		Controller:          did,
		DIDDocumentMetadata: map[string]interface{}{},
	}, nil
}
