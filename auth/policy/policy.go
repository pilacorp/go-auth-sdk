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
// DefaultAllowList() automatically.
//
// Example usage:
//
//	customAllow := NewAllowList(
//		[]ActionObject{ActionObjectIssuer},
//		[]ActionVerb{ActionVerbCreate},
//		[]ResourceObject{ResourceObjectIssuer},
//	)
//	policy := NewPolicy(
//		WithAllowList(customAllow),
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

// AdminList represents a list of action objects, action verbs, and resource objects that are allowed to construct permission statements.
type AllowList struct {
	ActionObjects   []ActionObject   `json:"actionObjects"`
	ActionVerbs     []ActionVerb     `json:"actionVerbs"`
	ResourceObjects []ResourceObject `json:"resourceObjects"`
}

// PolicyOption configures a Policy during construction.
type PolicyOption func(*Policy)

// WithAllowList sets a custom allow list for the policy.
// If allowList is zero-value, the policy keeps the default allow list.
func WithAllowList(allowList AllowList) PolicyOption {
	return func(p *Policy) {
		if len(allowList.ActionObjects) == 0 &&
			len(allowList.ActionVerbs) == 0 &&
			len(allowList.ResourceObjects) == 0 {
			return
		}
		p.AllowList = allowList
	}
}

// WithStatements appends permission statements to the policy.
func WithStatements(statements ...Statement) PolicyOption {
	return func(p *Policy) {
		p.Permissions = append(p.Permissions, statements...)
	}
}

// NewAllowList constructs a AllowList from the given action objects, action verbs, and resource objects.
func NewAllowList(actionObjects []ActionObject, actionVerbs []ActionVerb, resourceObjects []ResourceObject) AllowList {
	return AllowList{
		ActionObjects:   actionObjects,
		ActionVerbs:     actionVerbs,
		ResourceObjects: resourceObjects,
	}
}

// DefaultAllowList constructs a AllowList with the default action objects, action verbs, and resource objects.
func DefaultAllowList() AllowList {
	return AllowList{
		ActionObjects:   []ActionObject{ActionObjectIssuer, ActionObjectDid, ActionObjectSchema, ActionObjectCredential, ActionObjectPresentation, ActionObjectAccessibleCredential, ActionObjectProvider, ActionObjectBaseSchema},
		ActionVerbs:     []ActionVerb{ActionVerbCreate, ActionVerbUpdate, ActionVerbDelete, ActionVerbRevoke, ActionVerbUpdateInfo, ActionVerbUpdatePermissions, ActionVerbGrantCreate, ActionVerbGrantUpdate, ActionVerbGrantDelete, ActionVerbGrantRevoke, ActionVerbGrantUpdateInfo, ActionVerbGrantUpdatePermissions},
		ResourceObjects: []ResourceObject{ResourceObjectIssuer, ResourceObjectDid, ResourceObjectSchema, ResourceObjectCredential, ResourceObjectPresentation, ResourceObjectAccessibleCredential, ResourceObjectProvider, ResourceObjectBaseSchema},
	}
}

// Policy represents a collection of permission statements.
type Policy struct {
	Permissions []Statement `json:"permissions"`
	AllowList   AllowList   `json:"allowList"`
}

// NewPolicy constructs a Policy from the given options.
// If no allow list option is provided, it defaults to DefaultAllowList().
func NewPolicy(options ...PolicyOption) Policy {
	p := Policy{
		AllowList: DefaultAllowList(),
	}
	for _, opt := range options {
		if opt == nil {
			continue
		}
		opt(&p)
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
	for _, stmt := range p.Permissions {
		if !stmt.isValid(p.AllowList) {
			return false
		}
	}
	return true
}

// matchObject checks if the action object matches the resource object.
func matchObject(action Action, resource Resource) bool {
	if action == AllAction || resource == AllResource {
		return true
	}

	return WildcardMatch(string(action.Object()), string(resource.Object()))
}
