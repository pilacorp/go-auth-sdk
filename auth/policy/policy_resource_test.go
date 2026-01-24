package policy

import "testing"

func TestResource_NewResourceAndString(t *testing.T) {
	r := NewResource(ResourceObjectIssuer)
	if r != Resource("Issuer:*") {
		t.Errorf("NewResource() = %v, want %v", r, Resource("Issuer:*"))
	}
	if r.String() != "Issuer:*" {
		t.Errorf("Resource.String() = %s, want %s", r.String(), "Issuer:*")
	}
}

func TestResource_NewObjectResource(t *testing.T) {
	r1 := NewObjectResource(ResourceObjectIssuer, "*")
	if r1 != Resource("Issuer:*") {
		t.Errorf("NewObjectResource(ResourceObjectIssuer, \"*\") = %v, want %v", r1, Resource("Issuer:*"))
	}

	r2 := NewObjectResource(ResourceObjectDid, "xyz")
	if r2 != Resource("Did:xyz") {
		t.Errorf("NewObjectResource(ResourceObjectDid, \"xyz\") = %v, want %v", r2, Resource("Did:xyz"))
	}
}

func TestResource_Matches(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
		target   string
		want     bool
	}{
		{
			name:     "exact match",
			resource: Resource("Issuer:did:123"),
			target:   "Issuer:did:123",
			want:     true,
		},
		{
			name:     "exact mismatch",
			resource: Resource("issuer:did:123"),
			target:   "Issuer:did:456",
			want:     false,
		},
		{
			name:     "global wildcard",
			resource: Resource("*"),
			target:   "Issuer:did:123",
			want:     true,
		},
		{
			name:     "prefix wildcard issuer all",
			resource: Resource("Issuer:*"),
			target:   "Issuer:did:123",
			want:     true,
		},
		{
			name:     "prefix wildcard did all",
			resource: Resource("Did:*"),
			target:   "Did:xyz",
			want:     true,
		},
		{
			name:     "prefix wildcard no match",
			resource: Resource("Issuer:"),
			target:   "Did:xyz",
			want:     false,
		},
		{
			name:     "complex prefix wildcard",
			resource: Resource("Issuer:*"),
			target:   "Issuer:abc",
			want:     true,
		},
		{
			name:     "complex prefix wildcard mismatch",
			resource: Resource("Issuer:*"),
			target:   "Schema:abc",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.resource.Matches(tt.target)
			if got != tt.want {
				t.Errorf("Resource.Matches(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestAnyResourceMatches(t *testing.T) {
	resources := []Resource{
		Resource("Issuer:did:123"),
		Resource("Did:*"),
	}

	if !AnyResourceMatches(resources, "Did:abc") {
		t.Errorf("AnyResourceMatches did not match target did:abc")
	}

	if AnyResourceMatches(resources, "Schema:1") {
		t.Errorf("AnyResourceMatches unexpectedly matched target schema:1")
	}
}
