package policy

import (
	"testing"
)

func TestNewPolicy(t *testing.T) {
	s1 := Statement{
		Effect:    EffectAllow,
		Actions:   []Action{NewAction("Issuer:*")},
		Resources: []Resource{NewResource(ResourceObjectIssuer)},
	}
	s2 := Statement{
		Effect:    EffectDeny,
		Actions:   []Action{NewAction("Issuer:UpdateInfo")},
		Resources: []Resource{NewResource(ResourceObjectIssuer)},
	}

	p := NewPolicy(WithStatements(s1, s2))

	if len(p.Permissions) != 2 {
		t.Fatalf("NewPolicy() len = %d, want %d", len(p.Permissions), 2)
	}

	gotFirst := p.Permissions[0]
	if gotFirst.Effect != s1.Effect {
		t.Errorf("NewPolicy() first Effect = %v, want %v", gotFirst.Effect, s1.Effect)
	}
	if len(gotFirst.Actions) != len(s1.Actions) {
		t.Fatalf("NewPolicy() first Actions len = %d, want %d", len(gotFirst.Actions), len(s1.Actions))
	}
	for i := range gotFirst.Actions {
		if gotFirst.Actions[i] != s1.Actions[i] {
			t.Errorf("NewPolicy() first Actions[%d] = %v, want %v", i, gotFirst.Actions[i], s1.Actions[i])
		}
	}
	if len(gotFirst.Resources) != len(s1.Resources) {
		t.Fatalf("NewPolicy() first Resources len = %d, want %d", len(gotFirst.Resources), len(s1.Resources))
	}
	for i := range gotFirst.Resources {
		if gotFirst.Resources[i] != s1.Resources[i] {
			t.Errorf("NewPolicy() first Resources[%d] = %v, want %v", i, gotFirst.Resources[i], s1.Resources[i])
		}
	}

	gotSecond := p.Permissions[1]
	if gotSecond.Effect != s2.Effect {
		t.Errorf("NewPolicy() second Effect = %v, want %v", gotSecond.Effect, s2.Effect)
	}
	if len(gotSecond.Actions) != len(s2.Actions) {
		t.Fatalf("NewPolicy() second Actions len = %d, want %d", len(gotSecond.Actions), len(s2.Actions))
	}
	for i := range gotSecond.Actions {
		if gotSecond.Actions[i] != s2.Actions[i] {
			t.Errorf("NewPolicy() second Actions[%d] = %v, want %v", i, gotSecond.Actions[i], s2.Actions[i])
		}
	}
	if len(gotSecond.Resources) != len(s2.Resources) {
		t.Fatalf("NewPolicy() second Resources len = %d, want %d", len(gotSecond.Resources), len(s2.Resources))
	}
	for i := range gotSecond.Resources {
		if gotSecond.Resources[i] != s2.Resources[i] {
			t.Errorf("NewPolicy() second Resources[%d] = %v, want %v", i, gotSecond.Resources[i], s2.Resources[i])
		}
	}
}

func TestPolicy_AddStatement(t *testing.T) {
	var p Policy

	if !p.IsEmpty() {
		t.Fatalf("empty policy IsEmpty() = false, want true")
	}

	s := Statement{
		Effect:    EffectAllow,
		Actions:   []Action{NewAction("issuer:*")},
		Resources: []Resource{NewResource(ResourceObjectIssuer)},
	}

	p.Permissions = append(p.Permissions, s)

	if p.IsEmpty() {
		t.Fatalf("policy IsEmpty() = true, want false")
	}
	if len(p.Permissions) != 1 {
		t.Fatalf("AddStatement() len = %d, want %d", len(p.Permissions), 1)
	}

	got := p.Permissions[0]
	if got.Effect != s.Effect {
		t.Errorf("AddStatement() Effect = %v, want %v", got.Effect, s.Effect)
	}
	if len(got.Actions) != len(s.Actions) {
		t.Fatalf("AddStatement() Actions len = %d, want %d", len(got.Actions), len(s.Actions))
	}
	for i := range got.Actions {
		if got.Actions[i] != s.Actions[i] {
			t.Errorf("AddStatement() Actions[%d] = %v, want %v", i, got.Actions[i], s.Actions[i])
		}
	}
	if len(got.Resources) != len(s.Resources) {
		t.Fatalf("AddStatement() Resources len = %d, want %d", len(got.Resources), len(s.Resources))
	}
	for i := range got.Resources {
		if got.Resources[i] != s.Resources[i] {
			t.Errorf("AddStatement() Resources[%d] = %v, want %v", i, got.Resources[i], s.Resources[i])
		}
	}
}

func TestPolicy_AddAllowAndAddDeny(t *testing.T) {
	var p Policy

	allowConditions := Condition{
		"StringNotEquals": {
			"issuer:created_by": "<provider_did>",
		},
	}
	p.AddAllow(
		[]Action{NewAction("issuer:*"), NewAction("did:*"), NewObjectAction(ActionObjectIssuer, ActionVerbGrantCreate)},
		[]Resource{NewResource(ResourceObjectIssuer), NewResource(ResourceObjectDid)},
		allowConditions,
	)

	denyConditions := Condition{
		"StringNotEquals": {
			"issuer:created_by": "<issuer_did>",
		},
	}
	p.AddDeny(
		[]Action{NewAction("issuer:updateInfo")},
		[]Resource{NewResource(ResourceObjectIssuer)},
		denyConditions,
	)

	if len(p.Permissions) != 2 {
		t.Fatalf("policy permissions len = %d, want %d", len(p.Permissions), 2)
	}

	allowStmt := p.Permissions[0]
	if allowStmt.Effect != EffectAllow {
		t.Errorf("allowStmt.Effect = %s, want %s", allowStmt.Effect, EffectAllow)
	}
	if len(allowStmt.Actions) != 3 {
		t.Errorf("allowStmt.Actions len = %d, want %d", len(allowStmt.Actions), 3)
	}
	if len(allowStmt.Resources) != 2 {
		t.Errorf("allowStmt.Resources len = %d, want %d", len(allowStmt.Resources), 2)
	}
	if allowStmt.Conditions["StringNotEquals"]["issuer:created_by"] != "<provider_did>" {
		t.Errorf("allowStmt.Conditions value = %s, want %s", allowStmt.Conditions["StringNotEquals"]["issuer:created_by"], "<provider_did>")
	}

	denyStmt := p.Permissions[1]
	if denyStmt.Effect != EffectDeny {
		t.Errorf("denyStmt.Effect = %s, want %s", denyStmt.Effect, EffectDeny)
	}
	if len(denyStmt.Actions) != 1 {
		t.Errorf("denyStmt.Actions len = %d, want %d", len(denyStmt.Actions), 1)
	}
	if len(denyStmt.Resources) != 1 {
		t.Errorf("denyStmt.Resources len = %d, want %d", len(denyStmt.Resources), 1)
	}
	if denyStmt.Conditions["StringNotEquals"]["issuer:created_by"] != "<issuer_did>" {
		t.Errorf("denyStmt.Conditions value = %s, want %s", denyStmt.Conditions["StringNotEquals"]["issuer:created_by"], "<issuer_did>")
	}
}

func TestPolicy_IsValid_EmptyPolicy(t *testing.T) {
	var p Policy
	if p.IsValid() {
		t.Error("IsValid() for empty policy = true, want false")
	}
}

func TestPolicy_IsValid_ValidPolicy(t *testing.T) {
	p := NewPolicy(
		WithStatements(
			Statement{
				Effect:    EffectAllow,
				Actions:   []Action{NewAction("Issuer:Create")},
				Resources: []Resource{NewResource(ResourceObjectIssuer)},
			},
		),
	)
	if !p.IsValid() {
		t.Error("IsValid() for valid policy = false, want true")
	}
}

func TestPolicy_IsValid_InvalidStatement(t *testing.T) {
	p := NewPolicy(
		WithStatements(
			Statement{
				Effect:    Effect("invalid"),
				Actions:   []Action{NewAction("Issuer:Create")},
				Resources: []Resource{NewResource(ResourceObjectIssuer)},
			},
		),
	)
	if p.IsValid() {
		t.Error("IsValid() for policy with invalid statement = true, want false")
	}
}

func TestValidateStatements_EmptyStatements(t *testing.T) {
	spec := DefaultSpecification()
	err := ValidateStatements([]Statement{}, spec)
	if err == nil {
		t.Error("ValidateStatements() with empty statements should return error")
	}
	if err.Error() != "statements list cannot be empty" {
		t.Errorf("ValidateStatements() error = %v, want 'statements list cannot be empty'", err)
	}
}

func TestValidateStatements_ValidStatements(t *testing.T) {
	spec := DefaultSpecification()
	statements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{NewAction("Issuer:Create")},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
	}

	err := ValidateStatements(statements, spec)
	if err != nil {
		t.Errorf("ValidateStatements() with valid statements error = %v, want nil", err)
	}
}

func TestValidateStatements_ValidMultipleStatements(t *testing.T) {
	spec := DefaultSpecification()
	statements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{NewAction("Issuer:Create"), NewAction("Issuer:Update")},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
		{
			Effect:    EffectDeny,
			Actions:   []Action{NewAction("Issuer:Delete")},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
	}

	err := ValidateStatements(statements, spec)
	if err != nil {
		t.Errorf("ValidateStatements() with valid multiple statements error = %v, want nil", err)
	}
}

func TestValidateStatements_WithCustomSpecification(t *testing.T) {
	// Create a custom specification with only Issuer actions and resources
	customSpec := NewSpecification(
		[]ActionObject{ActionObjectIssuer},
		[]ActionVerb{ActionVerbCreate, ActionVerbDelete},
		[]ResourceObject{ResourceObjectIssuer},
	)

	// Valid statements for custom spec
	validStatements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{NewAction("Issuer:Create")},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
	}

	err := ValidateStatements(validStatements, customSpec)
	if err != nil {
		t.Errorf("ValidateStatements() with custom spec and valid statements error = %v, want nil", err)
	}

	// Invalid statements (action not in custom spec)
	invalidStatements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{NewAction("Did:Create")},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
	}

	err = ValidateStatements(invalidStatements, customSpec)
	if err == nil {
		t.Error("ValidateStatements() with action not in custom specification should return error")
	}
}

func TestValidateStatements_EmptyActions(t *testing.T) {
	spec := DefaultSpecification()
	statements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
	}

	err := ValidateStatements(statements, spec)
	if err == nil {
		t.Error("ValidateStatements() with empty actions should return error")
	}
	if err.Error() != "invalid statements: one or more statements are malformed" {
		t.Errorf("ValidateStatements() error = %v, want 'invalid statements: one or more statements are malformed'", err)
	}
}

func TestValidateStatements_EmptyResources(t *testing.T) {
	spec := DefaultSpecification()
	statements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{NewAction("Issuer:Create")},
			Resources: []Resource{},
		},
	}

	err := ValidateStatements(statements, spec)
	if err == nil {
		t.Error("ValidateStatements() with empty resources should return error")
	}
	if err.Error() != "invalid statements: one or more statements are malformed" {
		t.Errorf("ValidateStatements() error = %v, want 'invalid statements: one or more statements are malformed'", err)
	}
}

func TestValidateStatements_InvalidEffect(t *testing.T) {
	spec := DefaultSpecification()
	statements := []Statement{
		{
			Effect:    Effect("invalid"),
			Actions:   []Action{NewAction("Issuer:Create")},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
	}

	err := ValidateStatements(statements, spec)
	if err == nil {
		t.Error("ValidateStatements() with invalid effect should return error")
	}
	if err.Error() != "invalid statements: one or more statements are malformed" {
		t.Errorf("ValidateStatements() error = %v, want 'invalid statements: one or more statements are malformed'", err)
	}
}

func TestValidateStatements_InvalidAction(t *testing.T) {
	spec := DefaultSpecification()
	statements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{NewAction("Invalid:Action")},
			Resources: []Resource{NewResource(ResourceObjectIssuer)},
		},
	}

	err := ValidateStatements(statements, spec)
	if err == nil {
		t.Error("ValidateStatements() with invalid action should return error")
	}
	if err.Error() != "invalid statements: one or more statements are malformed" {
		t.Errorf("ValidateStatements() error = %v, want 'invalid statements: one or more statements are malformed'", err)
	}
}

func TestValidateStatements_InvalidResource(t *testing.T) {
	spec := DefaultSpecification()
	statements := []Statement{
		{
			Effect:    EffectAllow,
			Actions:   []Action{NewAction("Issuer:Create")},
			Resources: []Resource{NewResource("InvalidResource")},
		},
	}

	err := ValidateStatements(statements, spec)
	if err == nil {
		t.Error("ValidateStatements() with invalid resource should return error")
	}
	if err.Error() != "invalid statements: one or more statements are malformed" {
		t.Errorf("ValidateStatements() error = %v, want 'invalid statements: one or more statements are malformed'", err)
	}
}

func TestPolicy_ToJSON(t *testing.T) {
	p := NewPolicy(
		WithStatements(
			NewStatement(
				EffectAllow,
				[]Action{NewAction("Issuer:Create")},
				[]Resource{NewResource(ResourceObjectIssuer)},
				NewCondition(),
			),
		),
	)

	b, err := p.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	if len(b) == 0 {
		t.Fatalf("ToJSON() returned empty bytes, want non-empty")
	}
}

func TestPolicy_String(t *testing.T) {
	p := NewPolicy(
		WithStatements(
			NewStatement(
				EffectAllow,
				[]Action{NewAction("Issuer:Create")},
				[]Resource{NewResource(ResourceObjectIssuer)},
				NewCondition(),
			),
		),
	)

	s := p.String()
	if s == "" {
		t.Fatalf("String() returned empty string, want non-empty")
	}

	// String() should be valid JSON for a policy.
	if _, err := PolicyFromJSONString(s); err != nil {
		t.Fatalf("String() output is not valid policy JSON: %v", err)
	}
}

func TestPolicyFromJSON(t *testing.T) {
	in := NewPolicy(
		WithStatements(
			NewStatement(
				EffectAllow,
				[]Action{NewAction("Issuer:Create")},
				[]Resource{NewResource(ResourceObjectIssuer)},
				NewCondition(),
			),
		),
	)

	b, err := in.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}

	out, err := PolicyFromJSON(b)
	if err != nil {
		t.Fatalf("PolicyFromJSON() error = %v, want nil", err)
	}
	if len(out.Permissions) != 1 {
		t.Fatalf("PolicyFromJSON() Permissions len = %d, want 1", len(out.Permissions))
	}
	if out.Permissions[0].Effect != EffectAllow {
		t.Fatalf("PolicyFromJSON() first Effect = %s, want %s", out.Permissions[0].Effect, EffectAllow)
	}
}

func TestPolicyFromJSONString(t *testing.T) {
	in := NewPolicy(
		WithStatements(
			NewStatement(
				EffectAllow,
				[]Action{NewAction("Issuer:Create")},
				[]Resource{NewResource(ResourceObjectIssuer)},
				NewCondition(),
			),
		),
	)

	s := in.String()
	out, err := PolicyFromJSONString(s)
	if err != nil {
		t.Fatalf("PolicyFromJSONString() error = %v, want nil", err)
	}
	if len(out.Permissions) != 1 {
		t.Fatalf("PolicyFromJSONString() Permissions len = %d, want 1", len(out.Permissions))
	}
	if out.Permissions[0].Effect != EffectAllow {
		t.Fatalf("PolicyFromJSONString() first Effect = %s, want %s", out.Permissions[0].Effect, EffectAllow)
	}
}
