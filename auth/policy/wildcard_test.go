package policy

import "testing"

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{"empty pattern both empty", "", "", true},
		{"empty pattern non-empty value", "", "a", false},
		{"exact match", "issuer:abc", "issuer:abc", true},
		{"exact mismatch", "issuer:abc", "issuer:def", false},
		{"star matches many", "issuer:*", "issuer:did:123", true},
		{"star matches empty suffix", "issuer:*", "issuer:", true},
		{"question matches single", "issuer:?bc", "issuer:abc", true},
		{"question mismatch length", "issuer:?bc", "issuer:zzbc", false},
		{"mixed star and question", "issuer:?id:*", "issuer:1id:xyz", true},
		{"global star", "*", "anything:here", true},
		{"admin action", "*", "*", true},
		{"admin resource", "issuer:*", "issuer:create", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WildcardMatch(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("WildcardMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}
