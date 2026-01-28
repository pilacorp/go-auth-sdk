package policy

import "testing"

func TestStatement_Helpers(t *testing.T) {
	cond := NewCondition()
	cond.Add("StringNotEquals", "issuer:created_by", "<provider_did>")

	s := NewStatement(EffectAllow, []Action{}, []Resource{}, nil)
	if s.Effect != EffectAllow {
		t.Errorf("NewStatement Effect = %v, want %v", s.Effect, EffectAllow)
	}

	s.AddAction(NewAction("issuer:*"))
	s.AddAction(NewAction("did:*"))
	if len(s.Actions) != 2 {
		t.Fatalf("Statement.Actions len = %d, want %d", len(s.Actions), 2)
	}
	if s.Actions[0] != NewAction("issuer:*") || s.Actions[1] != NewAction("did:*") {
		t.Errorf("Statement.Actions = %v, want [%v %v]", s.Actions, NewAction("issuer:*"), NewAction("did:*"))
	}

	s.AddResource(NewResource("issuer:*"))
	s.AddResource(NewResource("did:*"))
	if len(s.Resources) != 2 {
		t.Fatalf("Statement.Resources len = %d, want %d", len(s.Resources), 2)
	}
	if s.Resources[0] != NewResource("issuer:*") || s.Resources[1] != NewResource("did:*") {
		t.Errorf("Statement.Resources = %v, want [%v %v]", s.Resources, NewResource("issuer:*"), NewResource("did:*"))
	}

	s.SetConditions(cond)
	if s.Conditions["StringNotEquals"]["issuer:created_by"] != "<provider_did>" {
		t.Errorf("Statement.Conditions value = %s, want %s", s.Conditions["StringNotEquals"]["issuer:created_by"], "<provider_did>")
	}
}

func TestStatement_EmptyActions(t *testing.T) {
	spec := DefaultSpecification()

	// Statement with empty actions should be invalid
	s := NewStatement(
		EffectAllow,
		[]Action{}, // Empty actions
		[]Resource{NewResource(ResourceObjectIssuer)},
		NewCondition(),
	)

	// Create a policy to test validation
	p := NewPolicy(
		WithSpecification(spec),
		WithStatements(s),
	)

	if p.IsValid() {
		t.Error("Statement with empty actions should be invalid")
	}
}

func TestStatement_EmptyResources(t *testing.T) {
	spec := DefaultSpecification()

	// Statement with empty resources should be invalid
	s := NewStatement(
		EffectAllow,
		[]Action{NewAction("Issuer:Create")},
		[]Resource{}, // Empty resources
		NewCondition(),
	)

	// Create a policy to test validation
	p := NewPolicy(
		WithSpecification(spec),
		WithStatements(s),
	)

	if p.IsValid() {
		t.Error("Statement with empty resources should be invalid")
	}
}

func TestStatement_EmptyActionsAndResources(t *testing.T) {
	spec := DefaultSpecification()

	// Statement with both empty actions and resources should be invalid
	s := NewStatement(
		EffectAllow,
		[]Action{},   // Empty actions
		[]Resource{}, // Empty resources
		NewCondition(),
	)

	// Create a policy to test validation
	p := NewPolicy(
		WithSpecification(spec),
		WithStatements(s),
	)

	if p.IsValid() {
		t.Error("Statement with empty actions and resources should be invalid")
	}
}

func TestStatement_ValidWithActionsAndResources(t *testing.T) {
	spec := DefaultSpecification()

	// Statement with both actions and resources should be valid (if actions and resources are valid)
	s := NewStatement(
		EffectAllow,
		[]Action{NewAction("Issuer:Create")},
		[]Resource{NewResource(ResourceObjectIssuer)},
		NewCondition(),
	)

	// Create a policy to test validation
	p := NewPolicy(
		WithSpecification(spec),
		WithStatements(s),
	)

	if !p.IsValid() {
		t.Error("Statement with valid actions and resources should be valid")
	}
}
