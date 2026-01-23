// Package policy defines the permission policy model used by the Auth SDK.
// Permissions are expressed as policy statements (effect/actions/resources/conditions)
// and embedded into VC-JWT under credentialSubject.permissions. This package will evolve to provide:
// - Types for policy statements and conditions
// - Builder helpers (allow/deny/action/resource/condition)
// - Validation utilities
// - Matching/evaluation helpers for services to enforce authorization decisions
package policy
