# Go Auth SDK

Go **Auth SDK** standardizes **Authentication + Authorization** using **Verifiable Credentials (VC)** (VC-JWT), so services in the ecosystem share a consistent security model.

## Goals

- **Policy-based permissions** (no “all-or-nothing” access).
- **Shared, consistent security logic** for sign/verify/parse/extract across services.
- **Pluggable signing**: local private key signer or Vault signer.

## End-to-end flow (VC-based)

- **Issuer issues a VC-JWT to the Holder**
  - Build an Authorization Credential: issuer DID, holder DID, schema ID, validity window, policy/permissions
  - Sign via local private key or Vault signer, then return the VC-JWT to the holder
- **Holder calls an API**
  - Send `Authorization: Bearer <vc-jwt>`
- **Service verifies & authorizes**
  - Verify signature, expiration, schema/issuer, and optional revocation
  - Extract issuer DID, holder DID, and permission list
  - The application enforces access based on the normalized output

## Permission model (policy statement)

Permissions are embedded under `credentialSubject.permissions` using a policy-statement model:
“who can do what, on which resources, under which conditions”.

```json
{
  "effect": "allow",
  "actions": ["Credential:Create"],
  "resources": ["Credential:*"],
  "conditions": {
    "StringEquals": { "tenant": "abc" }
  }
}
```

## Repo structure

- `auth/`: Facade API (builder/verifier) for VC-JWT auth.
- `auth/policy/`: Policy/permission types and validation helpers.
- `provider/`: Signing provider (Signer interface + implementations: private key / Vault).
- `examples/`: Examples.

