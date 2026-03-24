# AGENT.md - AI/LLM Coding Assistant Guide

This document provides guidance for AI coding assistants (LLMs) working with the go-auth-sdk.

## Overview

Go Auth SDK provides authentication and authorization using Verifiable Credentials (VC-JWT) and Verifiable Presentations (VP-JWT). It enables services to share a consistent security model with policy-based permissions.

**Module:** `github.com/pilacorp/go-auth-sdk`
**Go Version:** 1.24.6+

## Package Structure

```
go-auth-sdk/
├── auth/
│   ├── builder/           # Current VC/VP builder package
│   ├── verifier/          # Current VC/VP verifier package
│   ├── model/             # Current shared data types
│   ├── policy/            # Policy/permission types
│   └── status/            # Status builder and status registration APIs
├── signer/                 # Signer interface + implementations
│   ├── signer.go          # Signer interface
│   ├── ecdsa/             # ECDSA local signer
│   └── vault/             # Vault remote signer
└── examples/              # Usage examples
```

## Common Usage Patterns

### Pattern 1: Build and Sign a Credential (Issuer)

```go
import (
    "context"
    "time"
    "github.com/pilacorp/go-auth-sdk/auth/builder"
    "github.com/pilacorp/go-auth-sdk/auth/model"
    "github.com/pilacorp/go-auth-sdk/auth/policy"
    "github.com/pilacorp/go-auth-sdk/signer"
    "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
    "github.com/pilacorp/go-credential-sdk/credential/vc"
)

// 1. Create policy with permissions
stmt := policy.NewStatement(
    policy.EffectAllow,
    []policy.Action{policy.NewAction("Credential:Create")},
    []policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
    policy.NewCondition(),
)
testPolicy := policy.NewPolicy(
    policy.WithStatements(stmt),
)

// 2. Create credential status (required for revocation)
credentialStatus := []vc.Status{
    {
        ID:                   "https://example.com/status/0#0",
        Type:                 "StatusList2021Entry",
        StatusPurpose:        "revocation",
        StatusListIndex:      "0",
        StatusListCredential: "https://example.com/status/0",
    },
}

// 3. Create signer (ECDSA or Vault)
ecdsaSigner := ecdsa.NewPrivSigner(nil)

// 4. Create builder with schema ID and signer
builder := builder.NewVCBuilder(
    builder.WithBuilderSchemaID("https://example.com/schema/v1"),
    builder.WithSigner(ecdsaSigner),
)

// 5. Build credential
validFrom := time.Now()
validUntil := time.Now().Add(24 * time.Hour)
result, err := builder.Build(ctx, model.VCData{
    IssuerDID:        "did:example:issuer",
    HolderDID:        "did:example:holder",
    Policy:           testPolicy,
    ValidFrom:        &validFrom,
    ValidUntil:       &validUntil,
    CredentialStatus: credentialStatus,
}, builder.WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

// result.Token contains the VC-JWT
```

### Pattern 2: Verify a Credential (Service)

```go
import "github.com/pilacorp/go-auth-sdk/auth/verifier"

// Verify with multiple options
result, err := verifier.Verify(
    ctx,
    []byte(credentialToken),
    verifier.WithVerifyProof(),                // verify signature
    verifier.WithCheckExpiration(),            // check validity period
    verifier.WithSchemaValidation(),           // validate schema
    verifier.WithCheckRevocation(),            // check revocation
    verifier.WithVerifySchemaID("https://example.com/schema/v1"),
    verifier.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
)

if err != nil {
    // Handle error - see Error Handling section
}

// Use result.IssuerDID, result.HolderDID, result.Permissions
```

### Pattern 3: Build a Presentation from Multiple VC Tokens (Holder)

```go
import (
    "context"
    "github.com/pilacorp/go-auth-sdk/auth"
    "github.com/pilacorp/go-auth-sdk/signer"
    "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
)

vpSigner := ecdsa.NewPrivSigner(nil)
vpBuilder := builder.NewVPBuilder(
    builder.WithVPSigner(vpSigner),
)

vpResp, err := vpBuilder.Build(context.Background(), model.VPData{
    HolderDID: "did:example:holder",
    VCTokens:  []string{vcToken1, vcToken2},
}, builder.WithVPSignerOptions(signer.WithPrivateKey(holderPrivateKeyBytes)))
if err != nil {
    // Handle error
}

// vpResp.Token contains VP-JWT
```

### Pattern 4: Verify a Presentation and Handle Embedded VCs (Service)

```go
import "github.com/pilacorp/go-auth-sdk/auth/verifier"

vpResult, err := verifier.VerifyPresentation(
    ctx,
    []byte(vpToken),
    verifier.WithVPVerifyProof(),
    verifier.WithVPCheckExpiration(),
    verifier.WithVPDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
)
if err != nil {
    // Handle error
}

// Access holder DID
holderDID := vpResult.HolderDID

// Each embedded VC is returned as a raw token. Verify each VC independently.
for i, vc := range vpResult.VCs {
    vcResult, err := verifier.Verify(ctx, []byte(vc.Token),
        verifier.WithVerifyProof(),
        verifier.WithCheckExpiration(),
        verifier.WithVerifyPermissions(),
        verifier.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
    )
    if err != nil {
        // Handle error per VC
    }
    // Apply business-specific logic for combining permissions
}
```

### Pattern 5: Custom Status Builder

```go
import "github.com/pilacorp/go-auth-sdk/auth/status"
import "github.com/pilacorp/go-credential-sdk/credential/vc"

// Implement StatusBuilder interface for custom status creation
type MyStatusBuilder struct {
    BaseURL   string
    AuthToken string
}

var _ status.StatusBuilder = (*MyStatusBuilder)(nil)

func (b *MyStatusBuilder) CreateStatus(ctx context.Context, issuerDID string) ([]vc.Status, error) {
    // Custom logic here
    return []vc.Status{{
        ID:                   "https://example.com/status/0#0",
        Type:                 "StatusList2021Entry",
        StatusPurpose:        "revocation",
        StatusListIndex:      "0",
        StatusListCredential: "https://example.com/status/0",
    }}, nil
}

// Usage
statusBuilder := &MyStatusBuilder{BaseURL: "...", AuthToken: "..."}
statuses, err := statusBuilder.CreateStatus(ctx, issuerDID)
```

### Pattern 6: Policy with Custom Specification

```go
// Use custom specification for different action/resource rules
customSpec := policy.NewSpecification(
    []policy.ActionObject{policy.ActionObjectIssuer, policy.ActionObjectCredential},
    []policy.ActionVerb{policy.ActionVerbCreate, policy.ActionVerbUpdate},
    []policy.ResourceObject{policy.ResourceObjectIssuer, policy.ResourceObjectCredential},
)

p := policy.NewPolicy(
    policy.WithSpecification(&customSpec),
    policy.WithStatements(stmt),
)
```

### Pattern 7: Using Vault Signer

```go
import "github.com/pilacorp/go-auth-sdk/signer/vault"

vaultSigner := vault.NewVaultSigner("https://vault.example.com", "vault-token")

builder := builder.NewVCBuilder(
    builder.WithBuilderSchemaID("https://example.com/schema/v1"),
    builder.WithSigner(vaultSigner),
)

result, err := builder.Build(ctx, model.VCData{
    IssuerDID:        "did:example:issuer",
    HolderDID:        "did:example:holder",
    Policy:           testPolicy,
    CredentialStatus: credentialStatus,
}, builder.WithSignerOptions(signer.WithSignerAddress("0x1234...")))
```

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `issuer must be a non-empty string` | IssuerDID is empty | Provide valid IssuerDID in VCData |
| `holder DID is required` | HolderDID is empty | Provide valid HolderDID in VCData |
| `credential status is required` | CredentialStatus is empty | Provide status from StatusBuilder |
| `schema ID is required` | SchemaID not set | Use WithBuilderSchemaID() |
| `signer is required` | No signer configured | Use WithSigner() |
| `failed to parse credential` | Invalid JWT format | Check credential token format |
| `permissions validation failed` | Invalid policy statements | Validate against specification |

### Best Practices for Error Handling

1. **Don't log in SDK** - Return errors to caller
2. **Wrap errors** - Use `%w` for error wrapping: `fmt.Errorf("failed to build: %w", err)`
3. **Check specific errors** - Compare against error messages or use errors.As for custom types (if implemented)

## Policy Actions and Resources

### Available Action Objects
- `policy.ActionObjectIssuer` - Issuer operations
- `policy.ActionObjectDid` - DID operations
- `policy.ActionObjectSchema` - Schema operations
- `policy.ActionObjectCredential` - Credential operations
- `policy.ActionObjectPresentation` - Presentation operations
- `policy.ActionObjectAccessibleCredential` - AccessibleCredential operations
- `policy.ActionObjectProvider` - Provider operations
- `policy.ActionObjectBaseSchema` - BaseSchema operations

### Available Action Verbs
- `policy.ActionVerbCreate` - Create
- `policy.ActionVerbUpdate` - Update
- `policy.ActionVerbDelete` - Delete
- `policy.ActionVerbRevoke` - Revoke
- `policy.ActionVerbUpdateInfo` - UpdateInfo
- `policy.ActionVerbUpdatePermissions` - UpdatePermissions
- `policy.ActionVerbGrantCreate` - GrantCreate
- `policy.ActionVerbGrantUpdate` - GrantUpdate
- `policy.ActionVerbGrantDelete` - GrantDelete
- `policy.ActionVerbGrantRevoke` - GrantRevoke
- `policy.ActionVerbGrantUpdateInfo` - GrantUpdateInfo
- `policy.ActionVerbGrantUpdatePermissions` - GrantUpdatePermissions

### Available Resource Objects
- `policy.ResourceObjectIssuer` - Issuer resource
- `policy.ResourceObjectDid` - DID resource
- `policy.ResourceObjectSchema` - Schema resource
- `policy.ResourceObjectCredential` - Credential resource
- `policy.ResourceObjectPresentation` - Presentation resource
- `policy.ResourceObjectAccessibleCredential` - AccessibleCredential resource
- `policy.ResourceObjectProvider` - Provider resource
- `policy.ResourceObjectBaseSchema` - BaseSchema resource

### Creating Actions/Resources

```go
// Action: "Object:Verb" format
action := policy.NewAction("Credential:Create")

// Resource: use predefined constants
resource := policy.NewResource(policy.ResourceObjectCredential)
```

## Signer Options

### ECDSA Signer

```go
// Method 1: Pass key at build time
ecdsaSigner := ecdsa.NewPrivSigner(privateKeyBytes)
result, err := builder.Build(ctx, data)

// Method 2: Pass key via options
ecdsaSigner := ecdsa.NewPrivSigner(nil)
result, err := builder.Build(ctx, data, builder.WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
```

### Vault Signer

```go
vaultSigner := vault.NewVaultSigner("https://vault.example.com", "vault-token")
result, err := builder.Build(ctx, data, builder.WithSignerOptions(signer.WithSignerAddress("0x1234...")))
```

## Verify Options

| Option | Purpose |
|--------|---------|
| `WithVerifyProof()` | Verify cryptographic signature |
| `WithCheckExpiration()` | Check validity period |
| `WithSchemaValidation()` | Validate against schema |
| `WithCheckRevocation()` | Check revocation status |
| `WithVerifySchemaID(id)` | Expect specific schema ID |
| `WithDIDBaseURL(url)` | DID resolution endpoint |
| `WithVerificationMethodKey(key)` | Verification method key (default: "key-1") |
| `WithSpecification(spec)` | Custom policy specification |
| `WithResolver(resolver)` | Custom DID resolver |

## VP Verify Options

| Option | Purpose |
|--------|---------|
| `WithVPVerifyProof()` | Verify VP cryptographic signature/proof |
| `WithVPCheckExpiration()` | Check VP validity period |
| `WithVPDIDBaseURL(url)` | DID resolution endpoint for VP proof verification |
| `WithVPVerificationMethodKey(key)` | Verification method key (default: `key-1`) |

**Note:** `VerifyPresentation` parses the VP and extracts holder DID + raw VC tokens. It does NOT auto-verify embedded VCs. Callers should call `auth.Verify` for each VC token based on their business logic.

## Testing Notes

- Unit tests use standard Go `testing` package
- Use `httptest.NewServer` for mock HTTP servers
- Test files are in same package with `_test.go` suffix
- Example test structure in `auth/auth_test.go`

## Configuration Best Practices

1. **Always validate inputs** - SDK validates required fields
2. **Use functional options** - Flexible configuration without breaking changes
3. **Pass context** - Always use `context.Context` for cancellable operations
4. **Handle errors** - Don't ignore returned errors
5. **Use interfaces** - Accept `Signer` interface, not concrete types

## Dependencies

- `github.com/ethereum/go-ethereum` - ECDSA key generation
- `github.com/google/uuid` - UUID generation
- `github.com/pilacorp/go-credential-sdk` - VC-JWT handling

## Common Integration Points

1. **Status Service** - Implement `status.StatusBuilder` interface for custom revocation or use `status.NewStatusBuilder()` with optional `StatusBuilderOption` (e.g. `status.WithStatusBuilderHTTPClient(customClient)`)
2. **DID Resolution** - Use `WithResolver()` for custom DID document resolution
3. **HTTP Client** - Configurable via `WithStatusBuilderHTTPClient()`; defaults to 10s timeout when not overridden
4. **Logging** - SDK does not log; handle in application layer
