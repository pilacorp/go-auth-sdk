# AGENT.md - AI/LLM Coding Assistant Guide

This document provides guidance for AI coding assistants (LLMs) working with the go-auth-sdk.

## Overview

Go Auth SDK provides authentication and authorization using Verifiable Credentials (VC-JWT) and Verifiable Presentations (VP-JWT). It enables services to share a consistent security model with policy-based permissions.

**Module:** `github.com/pilacorp/go-auth-sdk`
**Go Version:** 1.24.6+

## Package Structure

```
go-auth-sdk/
├── auth/                    # Main API for building/verifying VC-JWT
│   ├── auth.go             # AuthBuilder - build credentials
│   ├── verifier.go         # Verify - verify credentials
│   ├── vp_builder.go       # VPBuilder - build presentations
│   ├── vp_verifier.go      # VerifyPresentation - verify presentations
│   ├── model.go            # Data types (AuthData, VerifyResult)
│   ├── status_builder.go  # StatusBuilder interface for revocation
│   └── policy/            # Policy/permission types
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
    "github.com/pilacorp/go-auth-sdk/auth"
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
builder := auth.NewAuthBuilder(
    auth.WithBuilderSchemaID("https://example.com/schema/v1"),
    auth.WithSigner(ecdsaSigner),
)

// 5. Build credential
validFrom := time.Now()
validUntil := time.Now().Add(24 * time.Hour)
result, err := builder.Build(ctx, auth.AuthData{
    IssuerDID:        "did:example:issuer",
    HolderDID:        "did:example:holder",
    Policy:           testPolicy,
    ValidFrom:        &validFrom,
    ValidUntil:       &validUntil,
    CredentialStatus: credentialStatus,
}, auth.WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

// result.Token contains the VC-JWT
```

### Pattern 2: Verify a Credential (Service)

```go
import "github.com/pilacorp/go-auth-sdk/auth"

// Verify with multiple options
result, err := auth.Verify(
    ctx,
    []byte(credentialToken),
    auth.WithVerifyProof(),                    // verify signature
    auth.WithCheckExpiration(),                // check validity period
    auth.WithSchemaValidation(),               // validate schema
    auth.WithCheckRevocation(),               // check revocation
    auth.WithVerifySchemaID("https://example.com/schema/v1"),
    auth.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
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
vpBuilder := auth.NewVPBuilder(
    auth.WithVPSigner(vpSigner),
)

vpResp, err := vpBuilder.Build(context.Background(), auth.VPData{
    HolderDID: "did:example:holder",
    VCTokens:  []string{vcToken1, vcToken2},
}, auth.WithVPSignerOptions(signer.WithPrivateKey(holderPrivateKeyBytes)))
if err != nil {
    // Handle error
}

// vpResp.Token contains VP-JWT
```

### Pattern 4: Verify a Presentation and Aggregate Permissions (Service)

```go
import "github.com/pilacorp/go-auth-sdk/auth"

vpResult, err := auth.VerifyPresentation(
    ctx,
    []byte(vpToken),
    auth.WithVPVerifyProof(),
    auth.WithVPCheckExpiration(),
    auth.WithVPValidateCredentials(),
    auth.WithVPDIDBaseURL("https://api.ndadid.vn/api/v1/did"),
)
if err != nil {
    // Handle error
}

// Use vpResult.HolderDID, vpResult.AllPermissions
```

### Pattern 5: Custom Status Builder

```go
import "github.com/pilacorp/go-auth-sdk/auth"
import "github.com/pilacorp/go-credential-sdk/credential/vc"

// Implement StatusBuilder interface for custom status creation
type MyStatusBuilder struct {
    BaseURL   string
    AuthToken string
}

var _ auth.StatusBuilder = (*MyStatusBuilder)(nil)

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

builder := auth.NewAuthBuilder(
    auth.WithBuilderSchemaID("https://example.com/schema/v1"),
    auth.WithSigner(vaultSigner),
)

result, err := builder.Build(ctx, auth.AuthData{
    IssuerDID:        "did:example:issuer",
    HolderDID:        "did:example:holder",
    Policy:           testPolicy,
    CredentialStatus: credentialStatus,
}, auth.WithSignerOptions(signer.WithSignerAddress("0x1234...")))
```

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `issuer must be a non-empty string` | IssuerDID is empty | Provide valid IssuerDID in AuthData |
| `holder DID is required` | HolderDID is empty | Provide valid HolderDID in AuthData |
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
result, err := builder.Build(ctx, data, auth.WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))
```

### Vault Signer

```go
vaultSigner := vault.NewVaultSigner("https://vault.example.com", "vault-token")
result, err := builder.Build(ctx, data, auth.WithSignerOptions(signer.WithSignerAddress("0x1234...")))
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
| `WithVPValidateCredentials()` | Enable embedded VC validation in parser |
| `WithVPDIDBaseURL(url)` | DID resolution endpoint for VP proof/VC verification |
| `WithVPVerificationMethodKey(key)` | Verification method key (default: `key-1`) |

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

1. **Status Service** - Implement `StatusBuilder` interface for custom revocation or use `auth.NewStatusBuilder()` with optional `StatusBuilderOption` (e.g. `auth.WithStatusBuilderHTTPClient(customClient)`)
2. **DID Resolution** - Use `WithResolver()` for custom DID document resolution
3. **HTTP Client** - Configurable via `WithStatusBuilderHTTPClient()`; defaults to 10s timeout when not overridden
4. **Logging** - SDK does not log; handle in application layer
