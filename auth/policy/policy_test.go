package policy

import "testing"

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
