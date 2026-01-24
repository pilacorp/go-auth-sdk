package policy

import "testing"

func TestPolicyConstant_DefaultAndAddMethods(t *testing.T) {
	t.Run("default contains known values", func(t *testing.T) {
		c := DefaultPolicyConstant()

		if !c.IsValidActionObject(ActionObjectIssuer) {
			t.Fatalf("IsValidActionObject(ActionObjectIssuer) = false, want true")
		}
		if !c.IsValidActionVerb(ActionVerbCreate) {
			t.Fatalf("IsValidActionVerb(ActionVerbCreate) = false, want true")
		}
		if !c.IsValidResourceObject(ResourceObjectIssuer) {
			t.Fatalf("IsValidResourceObject(ResourceObjectIssuer) = false, want true")
		}
	})

	t.Run("unknown values are invalid by default", func(t *testing.T) {
		c := DefaultPolicyConstant()

		if c.IsValidActionObject(ActionObject("CustomObject")) {
			t.Fatalf("IsValidActionObject(CustomObject) = true, want false")
		}
		if c.IsValidActionVerb(ActionVerb("CustomVerb")) {
			t.Fatalf("IsValidActionVerb(CustomVerb) = true, want false")
		}
		if c.IsValidResourceObject(ResourceObject("CustomResourceObject")) {
			t.Fatalf("IsValidResourceObject(CustomResourceObject) = true, want false")
		}
	})

	t.Run("AddActionObject appends and becomes valid", func(t *testing.T) {
		c := DefaultPolicyConstant()
		before := len(c.ActionObjects)

		custom := ActionObject("CustomObject")
		c.AddActionObject(custom)

		if got := len(c.ActionObjects); got != before+1 {
			t.Fatalf("len(ActionObjects) = %d, want %d", got, before+1)
		}
		if !c.IsValidActionObject(custom) {
			t.Fatalf("IsValidActionObject(CustomObject) = false, want true")
		}
	})

	t.Run("AddActionVerb appends and becomes valid", func(t *testing.T) {
		c := DefaultPolicyConstant()
		before := len(c.ActionVerbs)

		custom := ActionVerb("CustomVerb")
		c.AddActionVerb(custom)

		if got := len(c.ActionVerbs); got != before+1 {
			t.Fatalf("len(ActionVerbs) = %d, want %d", got, before+1)
		}
		if !c.IsValidActionVerb(custom) {
			t.Fatalf("IsValidActionVerb(CustomVerb) = false, want true")
		}
	})

	t.Run("AddResourceObject appends and becomes valid", func(t *testing.T) {
		c := DefaultPolicyConstant()
		before := len(c.ResourceObject)

		custom := ResourceObject("CustomResourceObject")
		c.AddResourceObject(custom)

		if got := len(c.ResourceObject); got != before+1 {
			t.Fatalf("len(ResourceObject) = %d, want %d", got, before+1)
		}
		if !c.IsValidResourceObject(custom) {
			t.Fatalf("IsValidResourceObject(CustomResourceObject) = false, want true")
		}
	})
}
