package verifier

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// PresentationRequiredPolicy is the termsOfUse type an issuer attaches to a
// credential that may only be consumed inside a Verifiable Presentation.
// builder.VCBuilder emits it when model.VCData.RequirePresentation is set.
const PresentationRequiredPolicy = "PresentationRequiredPolicy"

// termsOfUseEntry models just enough of a credential to read its terms of use.
//
// vc.CredentialContents cannot be used here: it is the builder's input shape,
// not a faithful DTO of the credential JSON. Unmarshalling a credential into it
// fails on `credentialStatus`, which serializes to an object for a single entry
// while the struct declares a slice — so every credential this SDK issues would
// come back as an error.
type termsOfUseEntry struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type credentialTermsOfUse struct {
	TermsOfUse []termsOfUseEntry `json:"termsOfUse"`
}

// RequiresPresentation reports whether a credential may only be consumed inside
// a Verifiable Presentation, by looking for a PresentationRequiredPolicy entry
// in its termsOfUse.
//
// The SDK issues that marker but deliberately does not enforce it: VCVerify has
// no way to know whether a token reached the caller on its own or inside a
// presentation, and only the relying party does. Call this where a bare token
// enters your service — an Authorization header, say — and reject the request
// when it returns true. A credential obtained through VerifyPresentation has
// already satisfied the condition.
//
//	required, err := verifier.RequiresPresentation(bearerToken)
//	if err != nil {
//		return err
//	}
//	if required {
//		return fmt.Errorf("credential must be presented inside a verifiable presentation")
//	}
//
// The credential is not verified here — this only reads what the token claims.
// Pair it with VCVerify; on its own it says nothing about authenticity.
func RequiresPresentation(token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("credential is empty")
	}

	cred, err := vc.ParseCredential([]byte(token))
	if err != nil {
		return false, fmt.Errorf("failed to parse credential: %w", err)
	}

	contents, err := cred.GetContents()
	if err != nil {
		return false, fmt.Errorf("failed to get credential contents: %w", err)
	}

	var parsed credentialTermsOfUse
	if err := json.Unmarshal(contents, &parsed); err != nil {
		return false, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	for _, term := range parsed.TermsOfUse {
		if term.Type == PresentationRequiredPolicy {
			return true, nil
		}
	}

	return false, nil
}
