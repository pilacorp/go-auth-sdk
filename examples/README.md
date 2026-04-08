# Examples

This directory contains runnable examples demonstrating Auth SDK usage.

## Examples

### 1. Build Credential

Shows how to create and sign a Verifiable Credential with permissions.

**Run:**
```bash
go run examples/build_credential/main.go
```

### 2. Verify Credential

Shows how to create a credential token and verify it.

**Run:**
```bash
go run examples/verify_credential/main.go
```

### 3. Create Policy

Shows how to create and validate policies with different configurations.

**Run:**
```bash
go run examples/create_policy/main.go
```

### 4. Verify Presentation

Shows end-to-end presentation flow: issue multiple VCs, create VP-JWT from them, then verify VP and parse/verify each embedded VC independently.

**Run:**
```bash
go run examples/verify_presentation/main.go
```

## Quick Start

### Building a Credential

```go
import (
    "context"
    "time"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/pilacorp/go-auth-sdk/auth/builder"
    "github.com/pilacorp/go-auth-sdk/auth/model"
    "github.com/pilacorp/go-auth-sdk/auth/policy"
    "github.com/pilacorp/go-auth-sdk/signer"
    "github.com/pilacorp/go-auth-sdk/signer/ecdsa"
    "github.com/pilacorp/go-credential-sdk/credential/vc"
)

// Generate private key
privateKey, _ := crypto.GenerateKey()
privateKeyBytes := crypto.FromECDSA(privateKey)

// Create policy
stmt := policy.NewStatement(
    policy.EffectAllow,
    []policy.Action{policy.NewAction("Credential:Create")},
    []policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
    policy.NewCondition(),
)
testPolicy := policy.NewPolicy(policy.WithStatements(stmt))

// Create credential status (required)
credentialStatus := []vc.Status{
    {
        ID:                   "https://example.com/status/0#0",
        Type:                 "StatusList2021Entry",
        StatusPurpose:        "revocation",
        StatusListIndex:      "0",
        StatusListCredential: "https://example.com/status/0",
    },
}

// Create signer
ecdsaSigner := ecdsa.NewPrivSigner(nil)

// Create VCBuilder
builder := builder.NewVCBuilder(
    builder.WithBuilderSchemaID("https://example.com/schema/v1"),
    builder.WithSigner(ecdsaSigner),
)

// Build credential
validFrom := time.Now()
validUntil := time.Now().Add(24 * time.Hour)
result, err := builder.Build(context.Background(), model.VCData{
    IssuerDID:        "did:example:issuer",
    HolderDID:        "did:example:holder",
    Policy:           testPolicy,
    CustomFields: map[string]any{
        "tenantId": "tenant-001",
        "role":     "admin",
    },
    ValidFrom:        &validFrom,
    ValidUntil:       &validUntil,
    CredentialStatus: credentialStatus,
}, builder.WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

if err != nil {
    // Handle error
}
```

### Verifying a Credential

```go
import "github.com/pilacorp/go-auth-sdk/auth/verifier"

result, err := verifier.Verify(
    context.Background(),
    credentialBytes,
    verifier.WithVerifyProof(),
    verifier.WithCheckExpiration(),
    verifier.WithDIDBaseURL("https://api.example.com/did"),
)
if err != nil {
    // Handle error
}

// Use result.IssuerDID, result.HolderDID, result.Permissions
```

### Building and Verifying a Presentation

> Note:
> - `WithVPResolver(...)` is optional.
> - Custom resolver-based VP proof verification is not supported yet in the current version.
> - For now, use `WithVPVerifyProof()` with DID base URL options for VP proof verification.

```go
// Build VP-JWT from one or many VC-JWT tokens
vpBuilder := builder.NewVPBuilder(builder.WithVPSigner(ecdsa.NewPrivSigner(nil)))

vpResp, err := vpBuilder.Build(
    context.Background(),
    model.VPData{
        HolderDID: "did:example:holder",
        VCTokens:  []string{vcToken1, vcToken2},
    },
    builder.WithVPSignerOptions(signer.WithPrivateKey(holderPrivateKeyBytes)),
)
if err != nil {
    // Handle error
}

// Verify VP-JWT (only VP-level verification, does NOT auto-verify embedded VCs)
vpResult, err := verifier.VerifyPresentation(
    context.Background(),
    []byte(vpResp.Token),
    verifier.WithVPVerifyProof(),
    verifier.WithVPCheckExpiration(),
    verifier.WithVPDIDBaseURL("https://api.example.com/did"),
)
if err != nil {
    // Handle error
}

// Verify each embedded VC independently based on your business logic
for i, vc := range vpResult.VCs {
    vcResult, err := verifier.Verify(ctx, []byte(vc.Token),
        verifier.WithVerifyProof(),
        verifier.WithCheckExpiration(),
        verifier.WithVerifyPermissions(),
        verifier.WithDIDBaseURL("https://api.example.com/did"),
    )
    if err != nil {
        // Handle error per VC
    }
    _ = vcResult // Use as needed: IssuerDID, HolderDID, Permissions
}
```
