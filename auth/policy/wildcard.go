package policy

// WildcardMatch matches a value against a pattern using '*' and '?' wildcards.
//   - '*' matches zero or more characters
//   - '?' matches exactly one character
//   - Other characters match exactly
//
// Examples:
//   - WildcardMatch("test*", "testing") returns true
//   - WildcardMatch("test?", "test1") returns true
//   - WildcardMatch("test?", "testing") returns false
func WildcardMatch(pattern, value string) bool {
	pLen := len(pattern)
	vLen := len(value)

	p := 0
	v := 0
	star := -1
	match := 0

	for v < vLen {
		if p < pLen && (pattern[p] == value[v] || pattern[p] == '?') {
			p++
			v++
			continue
		}

		if p < pLen && pattern[p] == '*' {
			star = p
			match = v
			p++
			continue
		}

		if star != -1 {
			p = star + 1
			match++
			v = match
			continue
		}

		return false
	}

	for p < pLen && pattern[p] == '*' {
		p++
	}

	return p == pLen
}
