## Go Auth SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/pilacorp/go-auth-sdk.svg)](https://pkg.go.dev/github.com/pilacorp/go-auth-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/pilacorp/go-auth-sdk?style=flat-square)](https://goreportcard.com/report/github.com/pilacorp/go-auth-sdk)
[![Release](https://img.shields.io/github/v/release/pilacorp/go-auth-sdk?include_prereleases&style=flat-square)](https://github.com/pilacorp/go-auth-sdk/releases)
[![License](https://img.shields.io/github/license/pilacorp/go-auth-sdk.svg?style=flat-square)](https://github.com/pilacorp/go-auth-sdk/blob/main/LICENSE)

Go **Auth SDK** standardizes **Authentication + Authorization** using **Verifiable Credentials (VC)** (VC-JWT), enabling services in the ecosystem to share a consistent security model.

### Features

- **Policy-based permissions**: fine-grained authorization by action/resource/condition, moving away from "all-or-nothing" access.
- **End-to-end VC-JWT flow**: build credential, sign, verify, extract permissions.
- **End-to-end VP-JWT flow**: build presentation from one or many VC tokens, verify presentation, and parse/verify embedded VCs independently.
- **Pluggable signer**: sign with local private key or Vault signer.
- **Status integration (revocation)**: supports `credentialStatus` for credential revocation checking.

### Installation

```bash
go get github.com/pilacorp/go-auth-sdk
```

### Quick Start / Usage

#### 1. Overview Flow

- **Issuer**: builds an Authorization Credential (VC-JWT) containing:
  - issuer DID, holder DID
  - schema ID
  - validity period (validFrom, validUntil)
  - permissions list (policy)
  - credentialStatus (revocation)
- **Sign credential**: uses `signer.Signer` (ECDSA or Vault) → produces VC-JWT.
- **Holder**: calls API with header `Authorization: Bearer <vc-jwt>`.
- **Service**: uses `verifier.Verify` to:
  - verify signature, expiration, schema, revocation (via options)
  - extract normalized issuer DID, holder DID, and permissions.
- **Holder (presentation)**: uses `builder.NewVPBuilder(...).Build(...)` to create a VP-JWT from one or many VC-JWTs.
- **Service (presentation)**: uses `verifier.VerifyPresentation` to verify VP, then parses and verifies each embedded VC independently based on business logic.

#### 2. Input Structure for Building: `AuthData`

```go
type AuthData struct {
	ID               string        // optional: credential ID, SDK auto-generates UUID if empty
	IssuerDID        string        // required: Issuer DID (the credential signer)
	HolderDID        string        // required: Holder DID (credentialSubject.id)
	Policy           policy.Policy // required: permissions list
	ValidFrom        *time.Time    // optional: credential validity start time
	ValidUntil       *time.Time    // optional: credential validity end time
	CredentialStatus []vc.Status   // required: status information (revocation) for revocation checking
}
```

- **IssuerDID**: DID of the system issuing the credential (e.g., Issuer service DID).
- **HolderDID**: DID of the user/subject who will hold the credential.
- **SchemaID**: Set via `WithBuilderSchemaID()` when creating the AuthBuilder.

- **Policy**: list of statements describing permissions. Policies should be created using `policy.NewPolicy()` to ensure proper initialization:

```go
stmt := policy.NewStatement(
	policy.EffectAllow,                              // "allow" or "deny"
	[]policy.Action{policy.NewAction("Credential:Create")}, // actions
	[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)}, // resources
	policy.NewCondition(),                           // conditions (can be empty)
)

// Method 1: Use default specification (recommended for most cases)
p := policy.NewPolicy(
	policy.WithStatements(stmt),
)

// Method 2: Use custom specification (if you need different action/resource validation rules)
customSpec := policy.NewSpecification(
	[]policy.ActionObject{policy.ActionObjectIssuer, policy.ActionObjectCredential},
	[]policy.ActionVerb{policy.ActionVerbCreate, policy.ActionVerbUpdate},
	[]policy.ResourceObject{policy.ResourceObjectIssuer, policy.ResourceObjectCredential},
)
p := policy.NewPolicy(
	policy.WithSpecification(&customSpec), // Pass pointer to allow reuse across multiple policies
	policy.WithStatements(stmt),
)
```

**Note about Policy creation:**
- Policies should be created using `policy.NewPolicy()` to ensure proper initialization.
- If a Policy is created directly (e.g., from JSON unmarshaling), methods will automatically use the default specification when `Specification` is `nil`.
- When using `WithSpecification()`, pass a pointer (`&spec`) to allow multiple policies to share the same specification instance (memory efficient).

 - **CredentialStatus** (required):
  - Used to attach status information to the credential (especially for revocation checking).
  - Data type: `[]vc.Status`.
  - Each time a new credential is built, the Issuer needs **at least one status entry** corresponding to the status service, then assigns it to this field.
  - Two main approaches:
    - **Use SDK's `StatusBuilder` interface**: implement `StatusBuilder` interface or use the default `auth.NewStatusBuilder()` which calls the status registry API and returns `[]vc.Status`.
    - **Manually create `vc.Status` struct**: if you already have status information, simply initialize according to the template below and assign to `CredentialStatus`.

**Creating Status with StatusBuilder:**

The SDK provides a `StatusBuilder` interface to help create credential status entries. You can use the default implementation or create your own.

**Method 1: Use the default StatusBuilder (recommended)**

```go
// Create a StatusBuilder using the default implementation
statusBuilder := auth.NewStatusBuilder(
	"Bearer <issuer-access-token>",
	"https://api.ndadid.vn/api/v1/credentials/status/register",
)
// This calls the status registry API: POST https://api.ndadid.vn/api/v1/credentials/status/register

statuses, err := statusBuilder.CreateStatus(ctx, "did:nda:testnet:0xISSUER")
if err != nil {
	log.Fatalf("create status error: %v", err)
}

// Use statuses in AuthData.CredentialStatus
```

**Method 2: Implement your own StatusBuilder**

If you need custom logic (different API, database lookup, etc.), implement the `StatusBuilder` interface:

```go
// Custom status builder example
type MyStatusBuilder struct {
	BaseURL   string
	AuthToken string
}

// Ensure MyStatusBuilder implements auth.StatusBuilder
var _ auth.StatusBuilder = (*MyStatusBuilder)(nil)

func (b *MyStatusBuilder) CreateStatus(ctx context.Context, issuerDID string) ([]vc.Status, error) {
	// Your custom logic here (HTTP call, DB lookup, etc.)
	// Return []vc.Status
	return []vc.Status{
		{
			ID:                   "did:.../credentials/status/0#0",
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://.../credentials/status/0",
		},
	}, nil
}

// Usage:
statusBuilder := &MyStatusBuilder{
	BaseURL:   "https://my-status-service",
	AuthToken: "Bearer ...",
}

statuses, err := statusBuilder.CreateStatus(ctx, issuerDID)
// Use statuses in AuthData.CredentialStatus
```

**Method 3: Manually create vc.Status**

If you already have status information from your status service:

```go
statuses := []vc.Status{
	{
		ID:                   "did:.../credentials/status/0#0",
		Type:                 "BitstringStatusListEntry",
		StatusPurpose:        "revocation",
		StatusListIndex:      "0",
		StatusListCredential: "https://.../credentials/status/0",
	},
}
// Use statuses directly in AuthData.CredentialStatus
```

#### 3. Signer (Signing Credentials)

The SDK supports 2 types of signers for signing credentials:

##### 3.1. ECDSA Signer (local private key)

ECDSA signer uses a local private key for signing.

`ecdsa.NewPrivSigner(privateKey []byte)` supports two ways to provide the private key:

- Pass the private key at construction time (embedded in the signer struct)
- Or pass the private key per call via `signer.WithPrivateKey()` (takes precedence)

**Method 1: Initialize with nil (no embedded key), pass key via options when signing**

```go
import "github.com/pilacorp/go-auth-sdk/signer/ecdsa"

ecdsaSigner := ecdsa.NewPrivSigner(nil)
// Private key must be passed via signer.WithPrivateKey() when calling Build()
resp, err := builder.Build(ctx, data, builder.WithSignerOptions(signer.WithPrivateKey(myPrivKeyBytes)))
```

**Method 2: Initialize with embedded key**

```go
import "github.com/pilacorp/go-auth-sdk/signer/ecdsa"

ecdsaSigner := ecdsa.NewPrivSigner(myPrivKeyBytes)
// Can use the embedded key, or override with signer.WithPrivateKey()
resp, err := builder.Build(ctx, data) // use key from struct
// or
resp, err := builder.Build(ctx, data, builder.WithSignerOptions(signer.WithPrivateKey(anotherKey))) // override with different key
```

**Private key priority:**
- If `signer.WithPrivateKey()` is passed in options → use key from options (highest priority)
- If not in options → use key from struct (if available)
- If neither is available → returns an error

##### 3.2. Vault Signer (remote signing service)

Vault signer signs credentials through a Vault service (suitable for production, keys not stored locally):

```go
import "github.com/pilacorp/go-auth-sdk/signer/vault"

vaultSigner := vault.NewVaultSigner("https://vault.example.com", "vault-token")
// Signer address must be passed via builder.WithSignerOptions(...) when calling Build()
resp, err := builder.Build(ctx, data, builder.WithSignerOptions(signer.WithSignerAddress("0x1234...")))
```

**Note:**
- Vault signer requires `signer.WithSignerAddress()` to specify the account address in Vault
- If signer address is not provided → will return an error

#### 4. Build Credential (Create VC-JWT)

```go
import (
	"context"
	"time"

	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
	"github.com/pilacorp/go-auth-sdk/auth/policy"
	"github.com/pilacorp/go-auth-sdk/signer"
	"github.com/pilacorp/go-auth-sdk/signer/ecdsa"
)

ctx := context.Background()

// Create status using StatusBuilder (see section 2 above for details)
statusBuilder := auth.NewStatusBuilder(
	"Bearer <issuer-access-token>",
	"https://api.ndadid.vn/api/v1/credentials/status/register",
)
statuses, err := statusBuilder.CreateStatus(ctx, "did:nda:testnet:0xISSUER")
if err != nil {
	log.Fatalf("create status error: %v", err)
}

// Create policy
stmt := policy.NewStatement(
	policy.EffectAllow,
	[]policy.Action{policy.NewAction("Credential:Create")},
	[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
	policy.NewCondition(),
)
p := policy.NewPolicy(policy.WithStatements(stmt))

// Create signer
ecdsaSigner := ecdsa.NewPrivSigner(nil)

// Create AuthBuilder with schema ID
authBuilder := builder.NewAuthBuilder(
	builder.WithBuilderSchemaID("https://example.com/schema/v1"),
	builder.WithSigner(ecdsaSigner),
)

// Build credential
validFrom := time.Now()
validUntil := time.Now().Add(24 * time.Hour)
result, err := authBuilder.Build(ctx, model.AuthData{
	IssuerDID:        "did:nda:testnet:0xISSUER",
	HolderDID:        "did:nda:testnet:0xHOLDER",
	Policy:           p,
	ValidFrom:        &validFrom,
	ValidUntil:       &validUntil,
	CredentialStatus: statuses,
}, builder.WithSignerOptions(signer.WithPrivateKey(myPrivKeyBytes)))

if err != nil {
	log.Fatalf("build credential error: %v", err)
}

// result.Token is the VC-JWT (JSON/JWT string) that you return to the client/holder.
fmt.Println("VC-JWT:", result.Token)
```

#### 5. Verify Credential (Check VC-JWT + Extract Permissions)

```go
import "github.com/pilacorp/go-auth-sdk/auth/verifier"

ctx := context.Background()

result, err := verifier.Verify(
	ctx,
	[]byte(credentialToken),
	verifier.WithVerifyProof(),                  // enable signature verification
	verifier.WithCheckExpiration(),              // check validity period
	verifier.WithSchemaValidation(),             // validate against schema
	verifier.WithCheckRevocation(),              // (optional) check status/revocation
	verifier.WithVerifySchemaID("https://example.com/schema/v1"), // expect correct schema ID
	verifier.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"), // URL to resolve DID document
)
if err != nil {
	log.Fatalf("verify credential error: %v", err)
}

fmt.Println("Issuer DID:", result.IssuerDID)
fmt.Println("Holder DID:", result.HolderDID)
fmt.Printf("Permissions: %+v\n", result.Permissions)
```

#### 6. Build and Verify Presentation (VP-JWT)

Use VP flow when a holder needs to present one or many VC-JWTs in a single signed presentation.

**Build VP:**

```go
import (
	"github.com/pilacorp/go-auth-sdk/auth/builder"
	"github.com/pilacorp/go-auth-sdk/auth/model"
)

vpSigner := ecdsa.NewPrivSigner(nil)
vpBuilder := builder.NewVPBuilder(
	builder.WithVPSigner(vpSigner),
)

vpResp, err := vpBuilder.Build(ctx, model.VPData{
	HolderDID: "did:nda:testnet:0xHOLDER",
	VCTokens:  []string{vcToken1, vcToken2},
}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderPrivateKeyBytes)))
if err != nil {
	log.Fatalf("build presentation error: %v", err)
}

fmt.Println("VP-JWT:", vpResp.Token)
```

**Verify VP:**

> Note:
> - `WithVPResolver(...)` is optional.
> - Custom resolver-based VP proof verification is not supported yet in the current version.
> - For now, use `WithVPVerifyProof()` with DID base URL options for VP proof verification.

```go
import "github.com/pilacorp/go-auth-sdk/auth/verifier"

vpResult, err := verifier.VerifyPresentation(
	ctx,
	[]byte(vpResp.Token),
	verifier.WithVPVerifyProof(),
	verifier.WithVPCheckExpiration(),
	verifier.WithVPDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
	verifier.WithVPVerificationMethodKey("key-1"),
)
if err != nil {
	log.Fatalf("verify presentation error: %v", err)
}

fmt.Println("Holder DID:", vpResult.HolderDID)

// Each embedded VC is returned as a raw token. Verify each VC independently
// based on your business logic (e.g., different schema, policy requirements).
for i, vc := range vpResult.VCs {
	vcResult, err := verifier.Verify(ctx, []byte(vc.Token),
		verifier.WithVerifyProof(),
		verifier.WithCheckExpiration(),
		verifier.WithVerifyPermissions(),
		verifier.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
		verifier.WithVerificationMethodKey("key-1"),
	)
	if err != nil {
		log.Fatalf("verify embedded vc[%d] error: %v", i, err)
	}
	fmt.Printf("VC[%d] from %s:\n", i, vcResult.IssuerDID)
	fmt.Printf("  Permissions: %+v\n", vcResult.Permissions)
}
```

### Repo Structure

- `auth/builder/`: Current VC/VP builder package.
- `auth/verifier/`: Current VC/VP verifier package.
- `auth/model/`: Shared request/response types.
- `auth/policy/`: Policy/permission data types and validation functions.
- `auth/`: Legacy compatibility layer kept during the package split transition.
- `signer/`: `Signer` interface + implementations: ECDSA signer, Vault signer.
- `examples/`: SDK usage examples.
