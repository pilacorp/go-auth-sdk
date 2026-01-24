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
// Example usage:
//
//	policy := NewPolicy()
//	policy.AddAllow(
//		[]Action{NewAction("Issuer:Create")},
//		[]Resource{NewResource(ResourceObjectIssuer)},
//		NewCondition(),
//	)
//	if policy.Allows(NewAction("Issuer:Create"), NewResource(ResourceObjectIssuer)) {
//		// Access granted
//	}
package policy

const (
	// AdminAction represents all actions (wildcard).
	AllAction string = "*"
	// AdminResource represents all resources (wildcard).
	AllResource string = "*"
)

// Policy represents a collection of permission statements.
type Policy struct {
	Permissions []Statement `json:"permissions"`
}

// NewPolicy constructs a Policy from the given statements.
func NewPolicy(statements ...Statement) Policy {
	return Policy{
		Permissions: statements,
	}
}

// AddStatement appends a single statement to the policy.
func (p *Policy) AddStatement(statement Statement) {
	p.Permissions = append(p.Permissions, statement)
}

// AddAllow adds an allow statement with the given actions, resources, and conditions.
func (p *Policy) AddAllow(actions []Action, resources []Resource, conditions Condition) {
	p.AddStatement(Statement{
		Effect:     EffectAllow,
		Actions:    actions,
		Resources:  resources,
		Conditions: conditions,
	})
}

// AddDeny adds a deny statement with the given actions, resources, and conditions.
func (p *Policy) AddDeny(actions []Action, resources []Resource, conditions Condition) {
	p.AddStatement(Statement{
		Effect:     EffectDeny,
		Actions:    actions,
		Resources:  resources,
		Conditions: conditions,
	})
}

// IsEmpty reports whether the policy has no statements.
func (p Policy) IsEmpty() bool {
	return len(p.Permissions) == 0
}

// EffectFor returns the resulting effect for the given action and resource.
// It evaluates deny statements before allow statements and respects
// wildcard patterns. Conditions are not evaluated (use EffectForWithAttributes
// to evaluate conditions). The second return value reports whether any
// statement matched.
func (p Policy) EffectFor(action, resource string) (Effect, bool) {
	return p.EffectForWithAttributes(action, resource, nil)
}

// EffectForWithAttributes returns the resulting effect for the given action,
// resource, and attributes. It evaluates deny statements before allow statements,
// respects wildcard patterns, and evaluates conditions if provided.
// The second return value reports whether any statement matched.
func (p Policy) EffectForWithAttributes(action, resource string, attrs map[string]string) (Effect, bool) {
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
		// Check conditions if present
		if len(stmt.Conditions) > 0 && !stmt.Conditions.Matches(attrs) {
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
		// Check conditions if present
		if len(stmt.Conditions) > 0 && !stmt.Conditions.Matches(attrs) {
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
	eff, ok := p.EffectFor(action.String(), resource.String())
	return ok && eff == EffectAllow
}

// AllowsWithAttributes reports whether the policy allows the given action on the
// given resource with the provided attributes for condition evaluation.
// Deny statements take precedence over allow statements.
func (p Policy) AllowsWithAttributes(action Action, resource Resource, attrs map[string]string) bool {
	eff, ok := p.EffectForWithAttributes(action.String(), resource.String(), attrs)
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
	for _, stmt := range p.Permissions {
		if !stmt.IsValid() {
			return false
		}
	}
	return true
}

// matchObject checks if the action object matches the resource object.
func matchObject(action Action, resource Resource) bool {
	if string(action) == AllAction || string(resource) == AllResource {
		return true
	}

	return WildcardMatch(string(action.Object()), string(resource.Object()))
}
