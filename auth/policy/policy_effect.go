package policy

// Effect represents the effect of a permission statement.
// An effect determines whether a statement allows or denies access.
type Effect string

const (
	// EffectAllow indicates that the statement allows the specified actions on the specified resources.
	EffectAllow Effect = "allow"
	// EffectDeny indicates that the statement denies the specified actions on the specified resources.
	EffectDeny Effect = "deny"
)

// NewEffect constructs an Effect from the given string, normalizing known values.
// If the value is "allow" or "deny" (case-sensitive), it returns the corresponding constant.
// Otherwise, it returns an Effect with the given value (which will not be valid).
func NewEffect(value string) Effect {
	switch value {
	case string(EffectAllow):
		return EffectAllow
	case string(EffectDeny):
		return EffectDeny
	default:
		return Effect(value)
	}
}

// IsValid reports whether the effect is one of the known valid values (EffectAllow or EffectDeny).
func (e Effect) IsValid() bool {
	return e == EffectAllow || e == EffectDeny
}
