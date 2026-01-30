// Package policy defines the permission policy model used by the Auth SDK.
// Permissions are expressed as policy statements (effect/actions/resources/conditions)
// and embedded into VC-JWT under credentialSubject.permissions.
//
// The package provides:
//   - Types for policy statements, actions, resources, effects, and conditions
//   - Builder helpers for constructing policies (allow/deny/action/resource/condition)
//   - Validation utilities to ensure policies are well-formed
//   - Matching/evaluation helpers for services to enforce authorization decisions
//
// NewPolicy accepts options; if no allow list option is provided, it uses
// DefaultSpecification() automatically.
//
// Example usage:
//
//	customSpecification := NewSpecification(
//		[]ActionObject{ActionObjectIssuer},
//		[]ActionVerb{ActionVerbCreate},
//		[]ResourceObject{ResourceObjectIssuer},
//	)
//	policy := NewPolicy(
//		WithSpecification(customSpecification),
//		WithStatements(
//			NewStatement(
//				EffectAllow,
//				[]Action{NewAction("Issuer:Create")},
//				[]Resource{NewResource(ResourceObjectIssuer)},
//				NewCondition(),
//			),
//		),
//	)
package policy

import (
	"encoding/json"
	"fmt"
)

// PolicyOption configures a Policy during construction.
type PolicyOption func(*Policy)

// WithSpecification sets a custom specification for the policy.
// If specification is zero-value, the policy keeps the default specification.
func WithSpecification(specification *Specification) PolicyOption {
	return func(p *Policy) {
		if specification == nil {
			spec := DefaultSpecification()
			p.Specification = &spec
		} else {
			p.Specification = specification
		}
	}
}

// WithStatements appends permission statements to the policy.
func WithStatements(statements ...Statement) PolicyOption {
	return func(p *Policy) {
		p.Permissions = append(p.Permissions, statements...)
	}
}

// Policy represents a collection of permission statements.
type Policy struct {
	Permissions   []Statement    `json:"permissions"`
	Specification *Specification `json:"specification"`
}

// NewPolicy constructs a Policy from the given options.
// If no specification option is provided, it defaults to DefaultSpecification().
func NewPolicy(options ...PolicyOption) Policy {
	p := Policy{}
	for _, opt := range options {
		if opt == nil {
			continue
		}
		opt(&p)
	}

	if p.Specification == nil {
		spec := DefaultSpecification()
		p.Specification = &spec
	}

	return p
}

// AddAllow adds an allow statement with the given actions, resources, and conditions.
func (p *Policy) AddAllow(actions []Action, resources []Resource, conditions Condition) {
	p.Permissions = append(p.Permissions,
		Statement{
			Effect:     EffectAllow,
			Actions:    actions,
			Resources:  resources,
			Conditions: conditions,
		},
	)
}

// AddDeny adds a deny statement with the given actions, resources, and conditions.
func (p *Policy) AddDeny(actions []Action, resources []Resource, conditions Condition) {
	p.Permissions = append(p.Permissions,
		Statement{
			Effect:     EffectDeny,
			Actions:    actions,
			Resources:  resources,
			Conditions: conditions,
		},
	)
}

// IsEmpty reports whether the policy has no statements.
func (p Policy) IsEmpty() bool {
	return len(p.Permissions) == 0
}

// effectFor returns the resulting effect for the given action,
// resource, and attributes. It evaluates deny statements before allow statements,
// respects wildcard patterns, and evaluates conditions if provided.
// The second return value reports whether any statement matched.
func (p Policy) effectFor(action, resource string) (Effect, bool) {
	// Evaluate deny statements first
	for _, stmt := range p.Permissions {
		if stmt.Effect != EffectDeny {
			continue
		}
		if !AnyActionMatches(stmt.Actions, action) {
			continue
		}
		if !AnyResourceMatches(stmt.Resources, resource) {
			continue
		}

		return EffectDeny, true
	}

	// Evaluate allow statements
	for _, stmt := range p.Permissions {
		if stmt.Effect != EffectAllow {
			continue
		}
		if !AnyActionMatches(stmt.Actions, action) {
			continue
		}
		if !AnyResourceMatches(stmt.Resources, resource) {
			continue
		}

		return EffectAllow, true
	}

	return Effect(""), false
}

// Allows reports whether the policy allows the given action on the given resource.
// Deny statements take precedence over allow statements.
// Conditions are not evaluated (use AllowsWithAttributes to evaluate conditions).
func (p Policy) Allows(action Action, resource Resource) bool {
	eff, ok := p.effectFor(action.String(), resource.String())
	return ok && eff == EffectAllow
}

// AllowStatement reports whether the policy allows all action-resource combinations
// in the given statement. Returns true only if all combinations are allowed.
func (p Policy) AllowStatement(stmt Statement) bool {
	for _, action := range stmt.Actions {
		for _, resource := range stmt.Resources {
			if !matchObject(action, resource) {
				continue
			}
			if !p.Allows(action, resource) {
				return false
			}
		}
	}

	return true
}

// IsValid checks if the policy is valid.
// A policy is valid if all its statements are valid.
func (p Policy) IsValid() bool {
	if len(p.Permissions) == 0 {
		return false
	}

	spec := DefaultSpecification()
	if p.Specification != nil {
		spec = *p.Specification
	}

	for _, stmt := range p.Permissions {
		if !stmt.isValid(spec) {
			return false
		}
	}
	return true
}

// ValidateStatements validates that the statements list is well-formed.
// It performs comprehensive validation of policy statements to ensure they
// conform to the provided policy specification.
//
// Validation checks:
//   - The statements list is not empty
//   - Each statement has a valid effect (EffectAllow or EffectDeny)
//   - Each statement has at least one action
//   - Each statement has at least one resource
//   - All actions are valid according to the provided policy specification
//   - All resources are valid according to the provided policy specification
//
// Returns an error if any validation check fails, with details about
// which statement and field caused the failure.
func ValidateStatements(statements []Statement, spec Specification) error {
	if len(statements) == 0 {
		return fmt.Errorf("statements list cannot be empty")
	}

	// Create a policy with the provided specification to validate statements
	pol := NewPolicy(
		WithSpecification(&spec),
		WithStatements(statements...),
	)

	// Validate the policy (this checks all statements)
	if !pol.IsValid() {
		return fmt.Errorf("invalid statements: one or more statements are malformed")
	}

	return nil
}

// ToJSON marshals the policy into its JSON representation.
func (p Policy) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// String returns the policy as a JSON string.
func (p Policy) String() string {
	data, _ := p.ToJSON()
	return string(data)
}

// PolicyFromJSON unmarshals a policy from raw JSON bytes.
func PolicyFromJSON(data []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// PolicyFromJSONString unmarshals a policy from a JSON string.
func PolicyFromJSONString(s string) (Policy, error) {
	return PolicyFromJSON([]byte(s))
}

// matchObject checks if the action object matches the resource object.
func matchObject(action Action, resource Resource) bool {
	if action == ActionAll || resource == ResourceAll {
		return true
	}

	return WildcardMatch(string(action.Object()), string(resource.Object()))
}
