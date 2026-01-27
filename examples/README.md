# Examples

This directory contains runnable examples demonstrating Auth SDK usage.

## Examples

### 1. `build_credential.go` - Building Credentials

Shows how to create and sign a Verifiable Credential with permissions.

**Run:**
```bash
go run examples/build_credential.go
```

### 2. `verify_credential.go` - Verifying Credentials

Shows how to create a credential token and verify it.

**Run:**
```bash
go run examples/verify_credential.go
```

### 3. `create_policy.go` - Creating Policies

Shows how to create and validate policies with different configurations.

**Run:**
```bash
go run examples/create_policy.go
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
)

// Generate private key
privateKey, _ := crypto.GenerateKey()
privateKeyBytes := crypto.FromECDSA(privateKey)

// Create signer and policy
ecdsaSigner := ecdsa.NewPrivSigner()
policy := policy.NewPolicy(
    policy.WithStatements(
        policy.NewStatement(
            policy.EffectAllow,
            []policy.Action{policy.NewAction("Credential:Create")},
            []policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
            policy.NewCondition(),
        ),
    ),
)

// Build credential
builder, _ := auth.NewAuthBuilder("did:example:issuer", "https://example.com/schema/v1", ecdsaSigner)
validFrom := time.Now()
validUntil := time.Now().Add(24 * time.Hour)
result, _ := builder.Build(context.Background(), auth.AuthData{
    HolderDID:  "did:example:holder",
    Policy:     policy,
    ValidFrom:  &validFrom,
    ValidUntil: &validUntil,
}, signer.WithPrivateKey(privateKeyBytes))
```

### Verifying a Credential

```go
import (
    "context"
    "github.com/pilacorp/go-auth-sdk/auth"
)

result, err := auth.Verify(
    context.Background(),
    credentialBytes,
    auth.WithVerifyProof(),
    auth.WithCheckExpiration(),
    auth.WithDIDBaseURL("https://api.example.com/did"),
)
```
