package policy

// Condition represents a set of key-value conditions grouped by operator.
// Conditions are used to add additional constraints to policy statements.
// The structure is: Condition[operator][key] = value
// Example: Condition{"StringEquals": {"tenant": "abc"}}
type Condition map[string]map[string]string

// NewCondition constructs an empty Condition map.
func NewCondition() Condition {
	return Condition{}
}

// Add inserts or updates a value for the given operator and key.
// If the condition is nil, this method does nothing.
// Example: condition.Add("StringEquals", "tenant", "abc")
func (c Condition) Add(operator, key, value string) {
	if c == nil {
		return
	}
	if _, ok := c[operator]; !ok {
		c[operator] = make(map[string]string)
	}
	c[operator][key] = value
}

// Matches checks if the condition matches the given attributes.
// Returns true if:
//   - The condition is empty (no conditions to check)
//   - All conditions are satisfied by the attributes
//
// Supported operators:
//   - "StringEquals": attribute value must match the pattern (supports wildcards)
//   - "StringNotEquals": attribute value must not match the pattern (supports wildcards)
//
// Returns false if:
//   - Any condition is not satisfied
//   - An unsupported operator is used
func (c Condition) Matches(attrs map[string]string) bool {
	if len(c) == 0 {
		return true
	}

	if attrs == nil {
		return true
	}

	for op, kv := range c {
		switch op {
		case "StringEquals":
			for key, pattern := range kv {
				v, ok := attrs[key]
				if !ok {
					return false
				}
				if !WildcardMatch(pattern, v) {
					return false
				}
			}
		case "StringNotEquals":
			for key, pattern := range kv {
				v, ok := attrs[key]
				if !ok {
					return false
				}
				if WildcardMatch(pattern, v) {
					return false
				}
			}
		default:
			return false
		}
	}

	return true
}
