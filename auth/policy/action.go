package policy

import (
	"strings"
)

// Action represents a permission action pattern.
// Actions follow the format "Object:Verb" (e.g., "Issuer:Create", "Credential:Update").
// The wildcard "*" represents all actions.
type Action string

// ActionObject represents the object part of an action (e.g., "Issuer", "Credential").
type ActionObject string

// ActionVerb represents the verb part of an action (e.g., "Create", "Update", "Delete").
type ActionVerb string

// NewAction constructs an Action from the given string.
// The string should follow the format "Object:Verb" or be "*" for all actions.
func NewAction(value string) Action {
	return Action(value)
}

// NewObjectAction constructs an Action from an object and a verb.
// Example: NewObjectAction(ActionObjectIssuer, ActionVerbCreate) returns "Issuer:Create".
func NewObjectAction(object ActionObject, verb ActionVerb) Action {
	return Action(string(object) + SeparatorChar + string(verb))
}

// String returns the underlying string value of the action.
func (a Action) String() string {
	return string(a)
}

// Object returns the object part of the action (everything before the colon).
// Returns an empty string if the action doesn't contain a colon.
func (a Action) Object() string {
	parts := strings.SplitN(string(a), SeparatorChar, 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[0]
}

// Verb returns the verb part of the action (everything after the colon).
// Returns an empty string if the action doesn't contain a colon.
func (a Action) Verb() string {
	parts := strings.SplitN(string(a), SeparatorChar, 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

// Matches reports whether the action pattern matches the target action string.
// Supports wildcard matching using '*' and '?' characters.
func (a Action) Matches(target string) bool {
	return WildcardMatch(string(a), target)
}

// AnyActionMatches reports whether any action in the slice matches the target string.
// Returns true if at least one action matches, false otherwise.
func AnyActionMatches(actions []Action, target string) bool {
	for _, act := range actions {
		if act.Matches(target) {
			return true
		}
	}

	return false
}

// isValid checks if the action is valid.
// Uses the constant set via SetCustomConstant() if available,
// otherwise uses the default policy constant.
func (a Action) isValid(specification Specification) bool {
	if a == ActionAll {
		return true
	}

	return a.isValidObject(specification) && a.isValidVerb(specification)
}

// isValidObject checks if the object of the action is valid.
// Uses the constant set via SetCustomConstant() if available,
// otherwise uses the default policy constant.
func (a Action) isValidObject(specification Specification) bool {
	if a == ActionAll {
		return true
	}

	obj := a.Object()
	if obj == "" {
		return false
	}

	for _, allowed := range specification.ActionObjects {
		if WildcardMatch(obj, string(allowed)) {
			return true
		}
	}

	return false
}

// isValidVerb checks if the verb of the action is valid.
// Uses the constant set via SetCustomConstant() if available,
// otherwise uses the default policy constant.
func (a Action) isValidVerb(specification Specification) bool {
	if a == ActionAll {
		return true
	}

	verb := a.Verb()
	if verb == "" {
		return false
	}

	for _, allowed := range specification.ActionVerbs {
		if WildcardMatch(verb, string(allowed)) {
			return true
		}
	}

	return false
}

// ToListActions converts a slice of strings to a slice of Action.
func ToListActions(actions []string) []Action {
	listActions := make([]Action, 0, len(actions))
	for _, action := range actions {
		listActions = append(listActions, Action(action))
	}

	return listActions
}
