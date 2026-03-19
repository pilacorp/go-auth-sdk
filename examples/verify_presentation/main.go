package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-auth-sdk/auth"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func main() {
	ctx := context.Background()

	fmt.Println("=== Full Verify Presentation Flow ===\n")

	// Step 1: Generate issuer and holder keys
	issuerKeyBytes, err := mustGeneratePrivateKey()
	if err != nil {
		log.Fatalf("generate issuer key failed: %v", err)
	}
	fmt.Println("✓ Generated issuer private key")

	holderKeyBytes, err := mustGeneratePrivateKey()
	if err != nil {
		log.Fatalf("generate holder key failed: %v", err)
	}
	fmt.Println("✓ Generated holder private key")

	// Step 2: Define DIDs and schema
	issuerDID := "did:example:issuer"
	holderDID := "did:example:user-holder"
	schemaID := "https://example.com/schema/v1"

	issuerPubHex, err := publicKeyHexFromPrivateKey(issuerKeyBytes)
	if err != nil {
		log.Fatalf("derive issuer public key failed: %v", err)
	}

	holderPubHex, err := publicKeyHexFromPrivateKey(holderKeyBytes)
	if err != nil {
		log.Fatalf("derive holder public key failed: %v", err)
	}

	// Start local DID resolver backed by generated issuer/holder public keys.
	// This keeps the example fully self-contained and avoids external DID dependency.
	resolverServer := startLocalDIDResolver(issuerDID, issuerPubHex, holderDID, holderPubHex)
	defer resolverServer.Close()

	didBaseURL := resolverServer.URL + "/api/v1/did"
	vp.Init(didBaseURL)
	vc.Init(didBaseURL)
	fmt.Printf("✓ Started local DID resolver: %s\n", didBaseURL)

	// Step 3: Create 3 policies with different permissions
	fmt.Println("\n--- Creating 3 Policies ---")

	policy1 := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Credential:Create")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)
	fmt.Println("✓ Policy 1: Credential:Create")

	policy2 := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Credential:Update")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)
	fmt.Println("✓ Policy 2: Credential:Update")

	policy3 := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Credential:Delete")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)
	fmt.Println("✓ Policy 3: Credential:Delete")

	// Step 4: Issue 3 VCs using AuthBuilder (one for each policy)
	fmt.Println("\n--- Issuing 3 VCs ---")

	vcTokens := make([]string, 0)

	credentialStatus := []vc.Status{
		{
			ID:                   "https://example.com/status/0#0",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.com/status/0",
		},
	}

	ecdsaSigner := ecdsa.NewPrivSigner(nil)
	builder := auth.NewAuthBuilder(
		auth.WithBuilderSchemaID(schemaID),
		auth.WithSigner(ecdsaSigner),
	)

	for i, p := range []*policy.Policy{&policy1, &policy2, &policy3} {
		resp, err := builder.Build(ctx, auth.AuthData{
			IssuerDID:        issuerDID,
			HolderDID:        holderDID,
			Policy:           *p,
			CredentialStatus: credentialStatus,
		}, auth.WithSignerOptions(signer.WithPrivateKey(issuerKeyBytes)))
		if err != nil {
			log.Fatalf("build vc[%d] failed: %v", i, err)
		}
		vcTokens = append(vcTokens, resp.Token)
		fmt.Printf("✓ Issued VC[%d]\n", i)
	}

	// Step 5: Create VP from VCs
	fmt.Println("\n--- Creating Verifiable Presentation ---")

	vcs := make([]vc.Credential, 0, len(vcTokens))
	for i, token := range vcTokens {
		credential, err := vc.ParseCredential([]byte(token))
		if err != nil {
			log.Fatalf("parse vc[%d] failed: %v", i, err)
		}
		vcs = append(vcs, credential)
	}

	contents := vp.PresentationContents{
		Context:               []any{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:full-flow-vp",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		ValidFrom:             time.Now(),
		ValidUntil:            time.Now().Add(5 * time.Minute),
		VerifiableCredentials: vcs,
	}

	presentation, err := vp.NewJWTPresentation(contents)
	if err != nil {
		log.Fatalf("new jwt presentation failed: %v", err)
	}
	fmt.Println("✓ Created JWT Presentation structure")

	// Step 6: Sign VP with holder key
	fmt.Println("\n--- Signing VP with holder key ---")

	holderKeyHex := fmt.Sprintf("%x", holderKeyBytes)
	if err := presentation.AddProof(holderKeyHex); err != nil {
		log.Fatalf("holder add vp proof failed: %v", err)
	}
	fmt.Println("✓ Added holder proof to VP")

	serialized, err := presentation.Serialize()
	if err != nil {
		log.Fatalf("serialize vp failed: %v", err)
	}

	vpToken, ok := serialized.(string)
	if !ok {
		log.Fatalf("invalid vp token type: expected string")
	}
	fmt.Printf("✓ Signed and serialized VP token\n")

	// Step 7: Sleep 5 seconds
	fmt.Println("\n--- Sleeping 5 seconds ---")
	time.Sleep(5 * time.Second)
	fmt.Println("✓ Waited 5 seconds")

	// Step 8: Verify VP and extract results
	fmt.Println("\n--- Verifying Presentation ---")

	vpResult, err := auth.VerifyPresentation(ctx, []byte(vpToken),
		auth.WithVPVerifyProof(),
		auth.WithVPCheckExpiration(),
		auth.WithVPDIDBaseURL(didBaseURL),
		auth.WithVPVerificationMethodKey("key-1"),
	)
	if err != nil {
		log.Fatalf("verify presentation failed: %v", err)
	}
	fmt.Println("✓ VP signature verified")
	fmt.Println("✓ VP expiration checked")
	fmt.Println("✓ All embedded VCs validated")

	// Step 9: Display VP Response
	fmt.Println("\n=== Verification Complete ===")
	fmt.Printf("Holder DID: %s\n", vpResult.HolderDID)
	fmt.Printf("Total Aggregated Permissions: %d\n", len(vpResult.AllPermissions))

	fmt.Println("\nAggregated Permission Statements:")
	for i, stmt := range vpResult.AllPermissions {
		fmt.Printf("  Statement[%d]:\n", i)
		fmt.Printf("    Effect: %v\n", stmt.Effect)
		for j, action := range stmt.Actions {
			fmt.Printf("    Action[%d]: %s\n", j, action)
		}
		for j, resource := range stmt.Resources {
			fmt.Printf("    Resource[%d]: %s\n", j, resource)
		}
	}

	fmt.Println("\n✅ Full presentation verification flow completed successfully!")
}

func mustGeneratePrivateKey() ([]byte, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return crypto.FromECDSA(privateKey), nil
}

func publicKeyHexFromPrivateKey(privateKeyBytes []byte) (string, error) {
	pk, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	pubBytes := crypto.FromECDSAPub(&pk.PublicKey)
	return hex.EncodeToString(pubBytes), nil
}

func startLocalDIDResolver(issuerDID, issuerPubHex, holderDID, holderPubHex string) *httptest.Server {
	buildDIDDoc := func(did, pubHex string) map[string]any {
		vmID := did + "#key-1"
		return map[string]any{
			"@context": []string{"https://www.w3.org/ns/did/v1"},
			"id":       did,
			"verificationMethod": []map[string]any{
				{
					"id":           vmID,
					"type":         "EcdsaSecp256k1VerificationKey2019",
					"controller":   did,
					"publicKeyHex": "0x" + pubHex,
				},
			},
			"authentication":      []string{vmID},
			"assertionMethod":     []string{vmID},
			"didDocumentMetadata": map[string]any{},
		}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/did/") {
			http.NotFound(w, r)
			return
		}

		didEncoded := strings.TrimPrefix(r.URL.Path, "/api/v1/did/")
		did, err := url.PathUnescape(didEncoded)
		if err != nil {
			http.Error(w, "invalid DID path", http.StatusBadRequest)
			return
		}

		var doc map[string]any
		switch did {
		case issuerDID:
			doc = buildDIDDoc(issuerDID, issuerPubHex)
		case holderDID:
			doc = buildDIDDoc(holderDID, holderPubHex)
		default:
			http.Error(w, "did not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	return httptest.NewServer(handler)
}
