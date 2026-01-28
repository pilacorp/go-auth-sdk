package policy

import "testing"

func TestAction_NewActionAndString(t *testing.T) {
	a := NewAction("Issuer:GrantCreate")
	if a != Action("Issuer:GrantCreate") {
		t.Errorf("NewAction() = %v, want %v", a, Action("Issuer:GrantCreate"))
	}
	if a.String() != "Issuer:GrantCreate" {
		t.Errorf("Action.String() = %s, want %s", a.String(), "Issuer:GrantCreate")
	}
}

func TestAction_Matches(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		target string
		want   bool
	}{
		{
			name:   "exact",
			action: NewAction("Issuer:Create"),
			target: "Issuer:Create",
			want:   true,
		},
		{
			name:   "wildcard issuer all",
			action: NewAction("Issuer:*"),
			target: "Issuer:UpdateInfo",
			want:   true,
		},
		{
			name:   "wildcard did all",
			action: NewAction("Did:*"),
			target: "Did:UpdateInfo",
			want:   true,
		},
		{
			name:   "mixed wildcard",
			action: NewAction("Issuer:?pdate*"),
			target: "Issuer:UpdatePermissions",
			want:   true,
		},
		{
			name:   "no match",
			action: NewAction("Issuer:Create"),
			target: "Did:Create",
			want:   false,
		},
		{
			name:   "no match",
			action: NewAction("Issuer:Create"),
			target: "Issuer:*Test",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.action.Matches(tt.target)
			if got != tt.want {
				t.Errorf("Action.Matches(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestAnyActionMatches(t *testing.T) {
	actions := []Action{
		NewAction("Issuer:Create"),
		NewAction("Did:*"),
	}

	if !AnyActionMatches(actions, "Did:UpdateInfo") {
		t.Errorf("AnyActionMatches did not match did:update_info")
	}

	if AnyActionMatches(actions, "Schema:Create") {
		t.Errorf("AnyActionMatches unexpectedly matched schema:create")
	}
}

func TestAction_isValidObject_WithWildcardObject(t *testing.T) {
	spec := DefaultSpecification()

	// "Iss*" should be considered valid because it matches "Issuer"
	a := NewAction("Iss*:Create")
	if !a.isValidObject(spec) {
		t.Errorf("isValidObject() for wildcard object Iss* = false, want true")
	}

	// Completely unknown object should still be invalid
	aInvalid := NewAction("Unknown*:Create")
	if aInvalid.isValidObject(spec) {
		t.Errorf("isValidObject() for Unknown* = true, want false")
	}
}
