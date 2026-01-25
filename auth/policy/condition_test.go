package policy

import "testing"

func TestCondition_NewConditionAndAdd(t *testing.T) {
	c := NewCondition()
	c.Add("StringNotEquals", "issuer:created_by", "<provider_did>")

	if len(c) != 1 {
		t.Fatalf("Condition len = %d, want %d", len(c), 1)
	}

	values, ok := c["StringNotEquals"]
	if !ok {
		t.Fatalf("Condition missing operator %q", "StringNotEquals")
	}
	if values["issuer:created_by"] != "<provider_did>" {
		t.Errorf("Condition value = %s, want %s", values["issuer:created_by"], "<provider_did>")
	}
}
