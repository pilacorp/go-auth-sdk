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

## Quick Start

### Building a Credential

```go
import (
    "context"
    "time"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/pilacorp/go-auth-sdk/auth"
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

// Create AuthBuilder
builder := auth.NewAuthBuilder(
    auth.WithBuilderSchemaID("https://example.com/schema/v1"),
    auth.WithSigner(ecdsaSigner),
)

// Build credential
validFrom := time.Now()
validUntil := time.Now().Add(24 * time.Hour)
result, err := builder.Build(context.Background(), auth.AuthData{
    IssuerDID:        "did:example:issuer",
    HolderDID:        "did:example:holder",
    Policy:           testPolicy,
    ValidFrom:        &validFrom,
    ValidUntil:       &validUntil,
    CredentialStatus: credentialStatus,
}, auth.WithSignerOptions(signer.WithPrivateKey(privateKeyBytes)))

if err != nil {
    // Handle error
}
```

### Verifying a Credential

```go
import "github.com/pilacorp/go-auth-sdk/auth"

result, err := auth.Verify(
    context.Background(),
    credentialBytes,
    auth.WithVerifyProof(),
    auth.WithCheckExpiration(),
    auth.WithDIDBaseURL("https://api.example.com/did"),
)
if err != nil {
    // Handle error
}

// Use result.IssuerDID, result.HolderDID, result.Permissions
```
