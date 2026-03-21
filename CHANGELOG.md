# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Released]

## [v1.1.0]

### Added
- Dedicated `auth/builder`, `auth/verifier`, and `auth/model` packages for the current VC/VP flow
- VP verifier support for DID base URL verification and custom resolver injection via `WithVPResolver(...)`
- Builder and verifier package tests covering the refactored VC/VP flows

### Changed
- Examples and integration tests now follow the package-split flow:
  - build via `auth/builder`
  - verify via `auth/verifier`
  - shared DTOs via `auth/model`
- `VerifyPresentation` examples and docs now use `VPVerifyResult.VCs`
- `examples/verify_credential` now runs self-contained with a static resolver instead of an external DID resolver

### Updated
- Documentation in `README.md`, `AGENT.md`, and `examples/README.md` for the `v1.1.0` package structure

## [v1.0.6]

### Fixed
- Update Document

### Changed
- Build validation: `Build()` now requires permissions in Policy - returns error "permissions are required" if empty

## [v1.0.5]

### Added
- Configurable HTTP client for `StatusBuilder` via `StatusBuilderOption` and `WithStatusBuilderHTTPClient()`
- Add tests in folder /test

### Updated
- Documentation (`README.md`, `AGENT.md`) to describe `StatusBuilder` options and HTTP client customization

## [v1.0.4]

### Added
- Action verb "get" support in policy

## [v1.0.3]

### Added
- Public key options for credential verification
- Schema loader for credential verification

### Updated
- go-credential-sdk to v1.5.8

## [v1.0.2]

### Added
- Enhanced verifier options with public key and schema validation support

### Updated
- go-credential-sdk to v1.5.7

## [v1.0.1]

### Added
- License file (MIT)

## [v1.0.0]

### Added
- Initial release of Go Auth SDK
- Policy-based permissions for fine-grained authorization
- VC-JWT credential building and verification
- ECDSA signer for local private key signing
- Vault signer for remote signing service
- Status integration (revocation) support with `credentialStatus`
- Schema validation for credentials
- AuthBuilder for credential creation

### Features
- `auth.Build()` - Build Verifiable Credentials (VC-JWT)
- `auth.Verify()` - Verify VC-JWT and extract permissions
- `policy.NewPolicy()` - Create authorization policies
- `signer/ecdsa` - ECDSA local private key signer
- `signer/vault` - Vault remote signer
- `StatusBuilder` interface for credential status creation

### Refactored
- Renamed `WithPublicKey` to `WithResolver` for clarity on resolver options
- Replaced public key with resolver provider in verifier options
- Renamed `AuthBuilderOption` to `AuthBuilderConfigOption`
- Modified `AuthBuilder` to use dedicated config field
- Updated `AuthBuilder` initialization to use `WithBuilderSchemaID`
### Fixed
- Removed unnecessary Host header from SignMessage request in Vault client
