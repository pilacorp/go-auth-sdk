## Go Auth SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/pilacorp/go-auth-sdk.svg)](https://pkg.go.dev/github.com/pilacorp/go-auth-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/pilacorp/go-auth-sdk?style=flat-square)](https://goreportcard.com/report/github.com/pilacorp/go-auth-sdk)
[![Release](https://img.shields.io/github/v/release/pilacorp/go-auth-sdk?include_prereleases&style=flat-square)](https://github.com/pilacorp/go-auth-sdk/releases)
[![License](https://img.shields.io/github/license/pilacorp/go-auth-sdk.svg?style=flat-square)](https://github.com/pilacorp/go-auth-sdk/blob/main/LICENSE)

Go **Auth SDK** standardizes **Authentication + Authorization** using **Verifiable Credentials (VC)** (VC-JWT), enabling services in the ecosystem to share a consistent security model.

### Features

- **Policy-based permissions**: fine-grained authorization by action/resource/condition, moving away from "all-or-nothing" access.
- **End-to-end VC-JWT flow**: build credential, sign, verify, extract permissions.
- **End-to-end VP-JWT flow**: build presentation from one or many VC tokens, verify presentation, and aggregate permissions from embedded VCs.
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
- **Service**: uses `auth.Verify` to:
  - verify signature, expiration, schema, revocation (via options)
  - extract normalized issuer DID, holder DID, and permissions.
- **Holder (presentation)**: uses `auth.NewVPBuilder(...).Build(...)` to create a VP-JWT from one or many VC-JWTs.
- **Service (presentation)**: uses `auth.VerifyPresentation` to verify VP and re-verify embedded VCs before aggregating permissions.

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
resp, err := builder.Build(ctx, data, auth.WithSignerOptions(signer.WithPrivateKey(myPrivKeyBytes)))
```

**Method 2: Initialize with embedded key**

```go
import "github.com/pilacorp/go-auth-sdk/signer/ecdsa"

ecdsaSigner := ecdsa.NewPrivSigner(myPrivKeyBytes)
// Can use the embedded key, or override with signer.WithPrivateKey()
resp, err := builder.Build(ctx, data) // use key from struct
// or
resp, err := builder.Build(ctx, data, auth.WithSignerOptions(signer.WithPrivateKey(anotherKey))) // override with different key
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
// Signer address must be passed via auth.WithSignerOptions(...) when calling Build()
resp, err := builder.Build(ctx, data, auth.WithSignerOptions(signer.WithSignerAddress("0x1234...")))
```

**Note:**
- Vault signer requires `signer.WithSignerAddress()` to specify the account address in Vault
- If signer address is not provided → will return an error

#### 4. Build Credential (Create VC-JWT)

```go
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
builder := auth.NewAuthBuilder(
	auth.WithBuilderSchemaID("https://example.com/schema/v1"),
	auth.WithSigner(ecdsaSigner),
)

// Build credential
validFrom := time.Now()
validUntil := time.Now().Add(24 * time.Hour)
result, err := builder.Build(ctx, auth.AuthData{
	IssuerDID:        "did:nda:testnet:0xISSUER",
	HolderDID:        "did:nda:testnet:0xHOLDER",
	Policy:           p,
	ValidFrom:        &validFrom,
	ValidUntil:       &validUntil,
	CredentialStatus: statuses,
}, auth.WithSignerOptions(signer.WithPrivateKey(myPrivKeyBytes)))

if err != nil {
	log.Fatalf("build credential error: %v", err)
}

// result.Token is the VC-JWT (JSON/JWT string) that you return to the client/holder.
fmt.Println("VC-JWT:", result.Token)
```

#### 5. Verify Credential (Check VC-JWT + Extract Permissions)

```go
ctx := context.Background()

result, err := auth.Verify(
	ctx,
	[]byte(credentialToken),
	auth.WithVerifyProof(),                  // enable signature verification
	auth.WithCheckExpiration(),              // check validity period
	auth.WithSchemaValidation(),             // validate against schema
	auth.WithCheckRevocation(),              // (optional) check status/revocation
	auth.WithVerifySchemaID("https://example.com/schema/v1"), // expect correct schema ID
	auth.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"), // URL to resolve DID document
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
vpSigner := ecdsa.NewPrivSigner(nil)
vpBuilder := auth.NewVPBuilder(
	auth.WithVPSigner(vpSigner),
)

vpResp, err := vpBuilder.Build(ctx, auth.VPData{
	HolderDID: "did:nda:testnet:0xHOLDER",
	VCTokens:  []string{vcToken1, vcToken2},
}, auth.WithVPSignerOptions(signer.WithPrivateKey(holderPrivateKeyBytes)))
if err != nil {
	log.Fatalf("build presentation error: %v", err)
}

fmt.Println("VP-JWT:", vpResp.Token)
```

**Verify VP:**

```go
vpResult, err := auth.VerifyPresentation(
	ctx,
	[]byte(vpResp.Token),
	auth.WithVPVerifyProof(),
	auth.WithVPCheckExpiration(),
	auth.WithVPValidateCredentials(),
	auth.WithVPDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
	auth.WithVPVerificationMethodKey("key-1"),
)
if err != nil {
	log.Fatalf("verify presentation error: %v", err)
}

fmt.Println("Holder DID:", vpResult.HolderDID)

// Process each embedded VC's verification result
// Implement custom aggregation/conflict resolution based on business logic
for i, vcResult := range vpResult.EmbeddedVCData {
	fmt.Printf("VC[%d] from %s:\n", i, vcResult.IssuerDID)
	fmt.Printf("  Permissions: %+v\n", vcResult.Permissions)
}
```

Optional anti-replay checks:
- `auth.WithVPVerifyAudience("expected-audience")`
- `auth.WithVPVerifyNonce("expected-nonce")`

### Repo Structure

- `auth/`: Main API for building/verifying VC-JWT.
- `auth/vp_builder.go`: VP builder for creating VP-JWT from VC tokens.
- `auth/vp_verifier.go`: VP verifier for VP proof/claims checks and embedded VC verification.
- `auth/policy/`: Policy/permission data types and validation functions.
- `signer/`: `Signer` interface + implementations: ECDSA signer, Vault signer.
- `examples/`: SDK usage examples.
