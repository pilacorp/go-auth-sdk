## Go Auth SDK

Go **Auth SDK** standardizes **Authentication + Authorization** using **Verifiable Credentials (VC)** (VC-JWT), enabling services in the ecosystem to share a consistent security model.

### Features

- **Policy-based permissions**: fine-grained authorization by action/resource/condition, moving away from "all-or-nothing" access.
- **End-to-end VC-JWT flow**: build credential, sign, verify, extract permissions.
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

#### 2. Input Structure for Building: `AuthData`

```go
type AuthData struct {
	ID               string        // optional: credential ID, SDK auto-generates UUID if empty
	IssuerDID        string        // required: Issuer DID (the credential signer)
	SchemaID         string        // optional: schema ID; uses DefaultSchemaID if empty
	HolderDID        string        // required: Holder DID (credentialSubject.id)
	Policy           policy.Policy // required: permissions list
	ValidFrom        *time.Time    // optional: credential validity start time
	ValidUntil       *time.Time    // optional: credential validity end time
	CredentialStatus []vc.Status   // required: status information (revocation) for revocation checking
}
```

- **IssuerDID**: DID of the system issuing the credential (e.g., Issuer service DID).
- **HolderDID**: DID of the user/subject who will hold the credential.
- **SchemaID**:
  - Used to validate credential structure on the verifier side.
  - If not provided, SDK uses the pre-configured `DefaultSchemaID` constant:

```go
const DefaultSchemaID = "https://auth-dev.pila.vn/api/v1/schemas/e8429e35-5486-4f05-a06c-2bd211f99fc8"
```

- **Policy**: list of statements describing permissions:

```go
stmt := policy.NewStatement(
	policy.EffectAllow,                              // "allow" or "deny"
	[]policy.Action{policy.NewAction("Credential:Create")}, // actions
	[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)}, // resources
	policy.NewCondition(),                           // conditions (can be empty)
)

p := policy.NewPolicy(
	policy.WithStatements(stmt),
)
```

- **CredentialStatus** (required):
  - Used to attach status information to the credential (especially for revocation checking).
  - Data type: `[]vc.Status`.
  - Each time a new credential is built, the Issuer needs **at least one status entry** corresponding to the status service, then assigns it to this field.
  - Two main approaches:
    - **Use SDK's `StatusBuilder` interface**: implement `StatusBuilder` interface or use the default `auth.NewDefaultStatusBuilder()` which calls the status registry API and returns `[]vc.Status`.
    - **Manually create `vc.Status` struct**: if you already have status information, simply initialize according to the template below and assign to `CredentialStatus`.

**Creating Status with StatusBuilder:**

The SDK provides a `StatusBuilder` interface to help create credential status entries. You can use the default implementation or create your own.

**Method 1: Use the default StatusBuilder (recommended)**

```go
// Create a StatusBuilder using the default implementation
statusBuilder := auth.NewDefaultStatusBuilder("Bearer <issuer-access-token>")
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
resp, err := auth.Build(ctx, data, ecdsaSigner, signer.WithPrivateKey(myPrivKeyBytes))
```

**Method 2: Initialize with embedded key**

```go
import "github.com/pilacorp/go-auth-sdk/signer/ecdsa"

ecdsaSigner := ecdsa.NewPrivSigner(myPrivKeyBytes)
// Can use the embedded key, or override with signer.WithPrivateKey()
resp, err := auth.Build(ctx, data, ecdsaSigner) // use key from struct
// or
resp, err := auth.Build(ctx, data, ecdsaSigner, signer.WithPrivateKey(anotherKey)) // override with different key
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
// Signer address must be passed via signer.WithSignerAddress() when calling Build()
resp, err := auth.Build(ctx, data, vaultSigner, signer.WithSignerAddress("0x1234..."))
```

**Note:**
- Vault signer requires `signer.WithSignerAddress()` to specify the account address in Vault
- If signer address is not provided → will return an error

#### 4. Build Credential (Create VC-JWT)

```go
ctx := context.Background()

// Create status using StatusBuilder (see section 2 above for details)
statusBuilder := auth.NewDefaultStatusBuilder("Bearer <issuer-access-token>")
statuses, err := statusBuilder.CreateStatus(ctx, "did:nda:testnet:0xISSUER")
if err != nil {
	log.Fatalf("create status error: %v", err)
}

data := auth.AuthData{
	IssuerDID: "did:nda:testnet:0xISSUER",
	HolderDID: "did:nda:testnet:0xHOLDER",
	Policy:    p,                 // policy.Policy from example above
	CredentialStatus: statuses,   // required: status for this credential (see section 2)
	// SchemaID: leave empty to use DefaultSchemaID
	// ValidFrom / ValidUntil: can be set if needed
}

// signer: can be ECDSA signer or Vault signer (see section 3 above)
ecdsaSigner := ecdsa.NewPrivSigner(nil)

resp, err := auth.Build(ctx, data, ecdsaSigner, signer.WithPrivateKey(myPrivKeyBytes))
if err != nil {
	log.Fatalf("build credential error: %v", err)
}

// resp.Token is the VC-JWT (JSON/JWT string) that you return to the client/holder.
fmt.Println("VC-JWT:", resp.Token)
```

#### 5. Verify Credential (Check VC-JWT + Extract Permissions)

```go
ctx := context.Background()

result, err := auth.Verify(
	ctx,
	[]byte(resp.Token),
	auth.WithVerifyProof(),                  // enable signature verification
	auth.WithCheckExpiration(),              // check validity period
	auth.WithSchemaValidation(),             // validate against schema
	auth.WithCheckRevocation(),              // (optional) check status/revocation
	auth.WithSchemaID(auth.DefaultSchemaID), // expect correct schema ID
	auth.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"), // URL to resolve DID document
)
if err != nil {
	log.Fatalf("verify credential error: %v", err)
}

fmt.Println("Issuer DID:", result.IssuerDID)
fmt.Println("Holder DID:", result.HolderDID)
fmt.Printf("Permissions: %+v\n", result.Permissions)
```

### Repo Structure

- `auth/`: Main API for building/verifying VC-JWT.
- `auth/policy/`: Policy/permission data types and validation functions.
- `signer/`: `Signer` interface + implementations: ECDSA signer, Vault signer.
- `examples/`: SDK usage examples.
