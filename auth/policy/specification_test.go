package policy

import "testing"

func TestNewSpecification(t *testing.T) {
	// Test with all parameters
	actionObjects := []ActionObject{ActionObjectIssuer, ActionObjectDid}
	actionVerbs := []ActionVerb{ActionVerbCreate, ActionVerbUpdate}
	resourceObjects := []ResourceObject{ResourceObjectIssuer, ResourceObjectDid}

	spec := NewSpecification(actionObjects, actionVerbs, resourceObjects)

	if len(spec.ActionObjects) != len(actionObjects) {
		t.Fatalf("NewSpecification() ActionObjects len = %d, want %d", len(spec.ActionObjects), len(actionObjects))
	}
	for i := range spec.ActionObjects {
		if spec.ActionObjects[i] != actionObjects[i] {
			t.Errorf("NewSpecification() ActionObjects[%d] = %v, want %v", i, spec.ActionObjects[i], actionObjects[i])
		}
	}

	if len(spec.ActionVerbs) != len(actionVerbs) {
		t.Fatalf("NewSpecification() ActionVerbs len = %d, want %d", len(spec.ActionVerbs), len(actionVerbs))
	}
	for i := range spec.ActionVerbs {
		if spec.ActionVerbs[i] != actionVerbs[i] {
			t.Errorf("NewSpecification() ActionVerbs[%d] = %v, want %v", i, spec.ActionVerbs[i], actionVerbs[i])
		}
	}

	if len(spec.ResourceObjects) != len(resourceObjects) {
		t.Fatalf("NewSpecification() ResourceObjects len = %d, want %d", len(spec.ResourceObjects), len(resourceObjects))
	}
	for i := range spec.ResourceObjects {
		if spec.ResourceObjects[i] != resourceObjects[i] {
			t.Errorf("NewSpecification() ResourceObjects[%d] = %v, want %v", i, spec.ResourceObjects[i], resourceObjects[i])
		}
	}

	// Test with nil inputs
	specEmpty := NewSpecification(nil, nil, nil)
	if len(specEmpty.ActionObjects) != 0 {
		t.Errorf("NewSpecification() with nil ActionObjects len = %d, want 0", len(specEmpty.ActionObjects))
	}
	if len(specEmpty.ActionVerbs) != 0 {
		t.Errorf("NewSpecification() with nil ActionVerbs len = %d, want 0", len(specEmpty.ActionVerbs))
	}
	if len(specEmpty.ResourceObjects) != 0 {
		t.Errorf("NewSpecification() with nil ResourceObjects len = %d, want 0", len(specEmpty.ResourceObjects))
	}

	// Test with partial inputs
	actionObjectsPartial := []ActionObject{ActionObjectIssuer}
	specPartial := NewSpecification(actionObjectsPartial, nil, nil)
	if len(specPartial.ActionObjects) != 1 {
		t.Errorf("NewSpecification() ActionObjects len = %d, want 1", len(specPartial.ActionObjects))
	}
	if specPartial.ActionObjects[0] != ActionObjectIssuer {
		t.Errorf("NewSpecification() ActionObjects[0] = %v, want %v", specPartial.ActionObjects[0], ActionObjectIssuer)
	}
	if len(specPartial.ActionVerbs) != 0 {
		t.Errorf("NewSpecification() ActionVerbs len = %d, want 0", len(specPartial.ActionVerbs))
	}
	if len(specPartial.ResourceObjects) != 0 {
		t.Errorf("NewSpecification() ResourceObjects len = %d, want 0", len(specPartial.ResourceObjects))
	}
}

func TestDefaultSpecification(t *testing.T) {
	spec := DefaultSpecification()

	// Test that it's not empty
	if len(spec.ActionObjects) == 0 {
		t.Fatalf("DefaultSpecification() ActionObjects is empty")
	}
	if len(spec.ActionVerbs) == 0 {
		t.Fatalf("DefaultSpecification() ActionVerbs is empty")
	}
	if len(spec.ResourceObjects) == 0 {
		t.Fatalf("DefaultSpecification() ResourceObjects is empty")
	}

	// Test ActionObjects contain known values
	knownActionObjects := []ActionObject{
		ActionObjectIssuer,
		ActionObjectDid,
		ActionObjectSchema,
		ActionObjectCredential,
	}
	for _, obj := range knownActionObjects {
		found := false
		for _, specObj := range spec.ActionObjects {
			if specObj == obj {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultSpecification() ActionObjects missing %v", obj)
		}
	}

	// Test ActionVerbs contain known values
	knownActionVerbs := []ActionVerb{
		ActionVerbCreate,
		ActionVerbUpdate,
		ActionVerbDelete,
		ActionVerbRevoke,
	}
	for _, verb := range knownActionVerbs {
		found := false
		for _, specVerb := range spec.ActionVerbs {
			if specVerb == verb {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultSpecification() ActionVerbs missing %v", verb)
		}
	}

	// Test grant verbs
	grantVerbs := []ActionVerb{
		ActionVerbGrantCreate,
		ActionVerbGrantUpdate,
		ActionVerbGrantDelete,
		ActionVerbGrantRevoke,
		ActionVerbGrantUpdateInfo,
		ActionVerbGrantUpdatePermissions,
	}
	for _, verb := range grantVerbs {
		found := false
		for _, specVerb := range spec.ActionVerbs {
			if specVerb == verb {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultSpecification() ActionVerbs missing grant verb %v", verb)
		}
	}

	// Test ResourceObjects contain known values
	knownResourceObjects := []ResourceObject{
		ResourceObjectIssuer,
		ResourceObjectDid,
		ResourceObjectSchema,
		ResourceObjectCredential,
	}
	for _, obj := range knownResourceObjects {
		found := false
		for _, specObj := range spec.ResourceObjects {
			if specObj == obj {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultSpecification() ResourceObjects missing %v", obj)
		}
	}

	// Test consistency across calls
	spec2 := DefaultSpecification()
	if len(spec.ActionObjects) != len(spec2.ActionObjects) {
		t.Errorf("DefaultSpecification() inconsistent ActionObjects len: %d vs %d", len(spec.ActionObjects), len(spec2.ActionObjects))
	}
	if len(spec.ActionVerbs) != len(spec2.ActionVerbs) {
		t.Errorf("DefaultSpecification() inconsistent ActionVerbs len: %d vs %d", len(spec.ActionVerbs), len(spec2.ActionVerbs))
	}
	if len(spec.ResourceObjects) != len(spec2.ResourceObjects) {
		t.Errorf("DefaultSpecification() inconsistent ResourceObjects len: %d vs %d", len(spec.ResourceObjects), len(spec2.ResourceObjects))
	}
}
