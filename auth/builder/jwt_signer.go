package builder

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/pilacorp/go-auth-sdk/signer"
	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

type jwtProofContainer interface {
	GetSigningInput() ([]byte, error)
	AddProofSignature(signature []byte) error
	Serialize() (interface{}, error)
}

type jwtCredential struct {
	vc.Credential
}

func (j jwtCredential) AddProofSignature(signature []byte) error {
	return j.Credential.AddCustomProof(&vcdto.Proof{
		Signature: signature,
	})
}

type jwtPresentation struct {
	vp.Presentation
}

func (j jwtPresentation) AddProofSignature(signature []byte) error {
	return j.Presentation.AddCustomProof(&vcdto.Proof{
		Signature: signature,
	})
}

func signAndSerializeJWT(
	ctx context.Context,
	obj jwtProofContainer,
	s signer.Signer,
	signOpts []signer.SignOption,
	kind string,
) (string, error) {
	signingInput, err := obj.GetSigningInput()
	if err != nil {
		return "", fmt.Errorf("failed to get %s signing input: %w", kind, err)
	}

	hash := sha256.Sum256(signingInput)

	signature, err := s.Sign(ctx, hash[:], signOpts...)
	if err != nil {
		return "", fmt.Errorf("failed to sign %s: %w", kind, err)
	}

	if err := obj.AddProofSignature(signature); err != nil {
		return "", fmt.Errorf("failed to add proof to %s: %w", kind, err)
	}

	serialized, err := obj.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize %s: %w", kind, err)
	}

	token, ok := serialized.(string)
	if !ok {
		return "", fmt.Errorf("invalid %s token type: expected string", kind)
	}

	return token, nil
}
