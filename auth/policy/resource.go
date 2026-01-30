package policy

import (
	"strings"
)

// Resource represents a resource identifier or pattern.
// Resources follow the format "Object:Suffix" (e.g., "Issuer:*", "Credential:123").
// The wildcard "*" represents all resources.
type Resource string

// ResourceObject represents the object part of a resource (e.g., "Issuer", "Credential").
type ResourceObject string

// NewResource constructs a Resource from the given object with a wildcard suffix.
// Example: NewResource(ResourceObjectIssuer) returns "Issuer:*".
func NewResource(object ResourceObject) Resource {
	return Resource(object) + ":*"
}

// NewObjectResource constructs a Resource from an object and a suffix.
// If suffix is empty, it defaults to "*".
// Example: NewObjectResource(ResourceObjectCredential, "123") returns "Credential:123".
func NewObjectResource(object ResourceObject, suffix string) Resource {
	if suffix == "" {
		return Resource(string(object) + SeparatorChar + "*")
	}

	return Resource(string(object) + SeparatorChar + suffix)
}

// String returns the underlying string value of the resource.
func (r Resource) String() string {
	return string(r)
}

// Matches reports whether the resource pattern matches the target resource string.
// Supports wildcard matching using '*' and '?' characters.
func (r Resource) Matches(target string) bool {
	return WildcardMatch(string(r), target)
}

// AnyResourceMatches reports whether any resource in the slice matches the target string.
// Returns true if at least one resource matches, false otherwise.
func AnyResourceMatches(resources []Resource, target string) bool {
	for _, r := range resources {
		if r.Matches(target) {
			return true
		}
	}

	return false
}

// isValid checks if the resource is valid.
// Uses the constant set via SetCustomConstant() if available,
// otherwise uses the default policy constant.
func (r Resource) isValid(specification Specification) bool {
	if r == ResourceAll {
		return true
	}

	obj := r.Object()
	if obj == "" {
		return false
	}

	for _, allowed := range specification.ResourceObjects {
		if WildcardMatch(string(obj), string(allowed)) {
			return true
		}
	}

	return false
}

// Object returns the object part of the resource.
// If the resource doesn't contain a colon, it returns an empty string.
func (r Resource) Object() string {
	parts := strings.SplitN(r.String(), SeparatorChar, 2)
	if len(parts) < 2 {
		return ""
	}

	return parts[0]
}

// Suffix returns the suffix part of the resource (everything after the colon).
// If the resource doesn't contain a colon, it returns an empty string.
func (r Resource) Suffix() string {
	parts := strings.SplitN(r.String(), SeparatorChar, 2)
	if len(parts) < 2 {
		return ""
	}

	return parts[1]
}

// ToListResources converts a slice of strings to a slice of Resource.
// No validation is performed; use IsValid() to validate each resource.
func ToListResources(resources []string) []Resource {
	listResources := make([]Resource, 0, len(resources))
	for _, resource := range resources {
		listResources = append(listResources, Resource(resource))
	}

	return listResources
}
