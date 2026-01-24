package policy

import (
	"encoding/json"
)

// Statement represents a single permission rule within a policy.
type Statement struct {
	Effect     Effect     `json:"effect"`
	Actions    []Action   `json:"actions"`
	Resources  []Resource `json:"resources"`
	Conditions Condition  `json:"conditions,omitempty"`
}

// NewStatement constructs a Statement from the given fields.
func NewStatement(effect Effect, actions []Action, resources []Resource, conditions Condition) Statement {
	return Statement{
		Effect:     effect,
		Actions:    actions,
		Resources:  resources,
		Conditions: conditions,
	}
}

// AddAction appends an action to the statement.
func (s *Statement) AddAction(action Action) {
	s.Actions = append(s.Actions, action)
}

// AddResource appends a resource to the statement.
func (s *Statement) AddResource(resource Resource) {
	s.Resources = append(s.Resources, resource)
}

// SetConditions sets the conditions for the statement.
func (s *Statement) SetConditions(conditions Condition) {
	s.Conditions = conditions
}

// IsValid checks if the statement is valid.
func (s *Statement) IsValid() bool {
	isActionValid := true
	for _, action := range s.Actions {
		if !action.IsValid() {
			isActionValid = false
			break
		}
	}

	isResourceValid := true
	for _, resource := range s.Resources {
		if !resource.IsValid() {
			isResourceValid = false
			break
		}
	}

	return s.Effect.IsValid() && isActionValid && isResourceValid
}

// ToResourceStringList returns the string representation of the resource.
func (s *Statement) ToResourceStringList() []string {
	resourceStrings := []string{}
	for _, resource := range s.Resources {
		resourceStrings = append(resourceStrings, resource.String())
	}
	return resourceStrings
}

// ToActionStringList returns the string representation of the action.
func (s *Statement) ToActionStringList() []string {
	actionStrings := []string{}
	for _, action := range s.Actions {
		actionStrings = append(actionStrings, action.String())
	}
	return actionStrings
}

// ToJSON returns the JSON representation of the statement.
func (s *Statement) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// ToJsonListStatements returns the JSON representation of the list of statements.
func ToJsonListStatements(statements []Statement) ([]byte, error) {
	return json.Marshal(statements)
}
