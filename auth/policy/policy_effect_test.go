package policy

import "testing"

func TestEffect_NewEffectAndIsValid(t *testing.T) {
	eAllow := NewEffect("allow")
	if eAllow != EffectAllow {
		t.Errorf("NewEffect(\"allow\") = %v, want %v", eAllow, EffectAllow)
	}
	if !eAllow.IsValid() {
		t.Errorf("EffectAllow.IsValid() = false, want true")
	}

	eDeny := NewEffect("deny")
	if eDeny != EffectDeny {
		t.Errorf("NewEffect(\"deny\") = %v, want %v", eDeny, EffectDeny)
	}
	if !eDeny.IsValid() {
		t.Errorf("EffectDeny.IsValid() = false, want true")
	}

	eCustom := NewEffect("custom")
	if eCustom != Effect("custom") {
		t.Errorf("NewEffect(\"custom\") = %v, want %v", eCustom, Effect("custom"))
	}
	if eCustom.IsValid() {
		t.Errorf("Effect(\"custom\").IsValid() = true, want false")
	}
}
