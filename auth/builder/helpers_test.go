package builder

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// defaultDIDBaseURL is go-credential-sdk's built-in DID resolver URL, used to
// restore package state after a test calls vc.Init / vp.Init.
const defaultDIDBaseURL = "https://api.ndadid.vn/api/v1/did"

// ecdsaPub aliases crypto/ecdsa.PublicKey for test files that import the
// signer/ecdsa package under the same name.
type ecdsaPub = ecdsa.PublicKey

// newTestKey generates a secp256k1 key and returns it with its raw private bytes.
func newTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	return priv, crypto.FromECDSA(priv)
}

// pubHex returns the uncompressed hex encoding of a secp256k1 public key.
func pubHex(pub *ecdsa.PublicKey) string {
	return hex.EncodeToString(crypto.FromECDSAPub(pub))
}

// newTestResolver returns an offline resolver holding one DID document per
// entry, each with a single "#key-1" VM listed in assertionMethod and
// authentication.
func newTestResolver(t *testing.T, keys map[string]*ecdsa.PublicKey) *verificationmethod.StaticResolver {
	t.Helper()
	r := verificationmethod.NewStaticResolver()
	for did, pub := range keys {
		r.Add(verificationmethod.NewDIDDocument(did, verificationmethod.NewSecp256k1VM(did, "key-1", pubHex(pub))))
	}
	return r
}

// decodeJWTPart decodes the header (index 0) or payload (index 1) of a JWT.
func decodeJWTPart(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT: %s", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("failed to decode JWT part %d: %v", index, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("failed to unmarshal JWT part %d: %v", index, err)
	}
	return m
}

func jwtHeader(t *testing.T, token string) map[string]any { return decodeJWTPart(t, token, 0) }

func jwtClaims(t *testing.T, token string) map[string]any { return decodeJWTPart(t, token, 1) }

// issuerResolver resolves "did:example:issuer" — the issuer the legacy
// builder tests use — to priv's public key under "#key-1".
func issuerResolver(t *testing.T, priv *ecdsa.PrivateKey) VCBuilderConfigOption {
	t.Helper()
	return WithBuilderResolver(newTestResolver(t, map[string]*ecdsa.PublicKey{"did:example:issuer": &priv.PublicKey}))
}

// twoKeyIssuerResolver publishes "did:example:issuer" with an unrelated
// "#key-1" and keyTwo under "#key-2", so only a pinned key-2 signs correctly.
func twoKeyIssuerResolver(t *testing.T, keyTwo *ecdsa.PublicKey) *verificationmethod.StaticResolver {
	t.Helper()
	other, _ := newTestKey(t)
	const did = "did:example:issuer"
	return verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(did,
		verificationmethod.NewSecp256k1VM(did, "key-1", pubHex(&other.PublicKey)),
		verificationmethod.NewSecp256k1VM(did, "key-2", pubHex(keyTwo)),
	))
}
