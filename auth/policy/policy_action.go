package policy

import (
	"errors"
	"strings"
)

const splitChar = ":"

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
	return Action(string(object) + splitChar + string(verb))
}

// String returns the underlying string value of the action.
func (a Action) String() string {
	return string(a)
}

// Object returns the object part of the action (everything before the colon).
// Returns an empty string if the action doesn't contain a colon.
func (a Action) Object() string {
	parts := strings.SplitN(string(a), splitChar, 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// Verb returns the verb part of the action (everything after the colon).
// Returns an empty string if the action doesn't contain a colon.
func (a Action) Verb() string {
	parts := strings.SplitN(string(a), splitChar, 2)
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

// IsValid checks if the action is valid.
// Uses the constant set via SetCustomConstant() if available,
// otherwise uses the default policy constant.
func (a Action) IsValid() bool {
	if a == "*" {
		return true
	}
	c := getActiveConstant()
	return a.IsValidObjectWith(c) && a.IsValidVerbWith(c)
}

// IsValidWith checks if the action is valid using the provided policy constants.
func (a Action) IsValidWith(c PolicyConstant) bool {
	if a == "*" {
		return true
	}

	return a.IsValidObjectWith(c) && a.IsValidVerbWith(c)
}

// IsValidObject checks if the object of the action is valid.
// Uses the constant set via SetCustomConstant() if available,
// otherwise uses the default policy constant.
func (a Action) IsValidObject() bool {
	if a == "*" {
		return true
	}
	c := getActiveConstant()
	return a.IsValidObjectWith(c)
}

// IsValidObjectWith checks if the object of the action is valid using
// the provided policy constants.
func (a Action) IsValidObjectWith(c PolicyConstant) bool {
	if a == "*" {
		return true
	}

	c = c.OrDefault()
	objectStr := a.Object()
	for _, obj := range c.ActionObjects {
		if WildcardMatch(string(obj), objectStr) {
			return true
		}
	}
	return false
}

// IsValidVerb checks if the verb of the action is valid.
// Uses the constant set via SetCustomConstant() if available,
// otherwise uses the default policy constant.
func (a Action) IsValidVerb() bool {
	if a == "*" {
		return true
	}
	c := getActiveConstant()
	return a.IsValidVerbWith(c)
}

// IsValidVerbWith checks if the verb of the action is valid using
// the provided policy constants.
func (a Action) IsValidVerbWith(c PolicyConstant) bool {
	if a == "*" {
		return true
	}

	c = c.OrDefault()
	verbStr := a.Verb()
	for _, verb := range c.ActionVerbs {
		if WildcardMatch(string(verb), verbStr) {
			return true
		}
	}
	return false
}

// ToActions parses a comma-separated string of actions into a slice of Action.
// Returns an error if any action is invalid.
// Example: ToActions("Issuer:Create,Did:Update") returns [Action("Issuer:Create"), Action("Did:Update")].
func ToActions(actionString string) ([]Action, error) {
	actionStrings := strings.Split(actionString, ",")
	actions := make([]Action, 0, len(actionStrings))
	for _, actionStr := range actionStrings {
		actionStr = strings.TrimSpace(actionStr)
		if actionStr == "" {
			continue
		}
		action := Action(actionStr)
		if !action.IsValid() {
			return nil, errors.New("invalid action: " + actionStr)
		}
		actions = append(actions, action)
	}
	return actions, nil
}

// ToGrantActions converts a slice of Action to a slice of grant actions.
// Each action is prefixed with "Grant" (e.g., "Issuer:Create" becomes "Issuer:GrantCreate").
func ToGrantActions(actions []Action) []Action {
	grantActions := make([]Action, 0, len(actions))
	for _, action := range actions {
		grantActions = append(grantActions, Action(action.Object()+":Grant"+action.Verb()))
	}
	return grantActions
}

// ToGrantAction converts an Action to a grant action.
// Example: "Issuer:Create" becomes "Issuer:GrantCreate".
func (a Action) ToGrantAction() Action {
	return Action(a.Object() + ":Grant" + a.Verb())
}

// ToListActions converts a slice of strings to a slice of Action.
// No validation is performed; use IsValid() to validate each action.
func ToListActions(actions []string) []Action {
	listActions := make([]Action, 0, len(actions))
	for _, action := range actions {
		listActions = append(listActions, Action(action))
	}
	return listActions
}
