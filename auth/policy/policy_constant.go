package policy

import "slices"

// Predefined action objects that can be used in actions.
const (
	ActionObjectIssuer               ActionObject = "Issuer"
	ActionObjectDid                  ActionObject = "Did"
	ActionObjectSchema               ActionObject = "Schema"
	ActionObjectCredential           ActionObject = "Credential"
	ActionObjectPresentation         ActionObject = "Presentation"
	ActionObjectAccessibleCredential ActionObject = "AccessibleCredential"
	ActionObjectProvider             ActionObject = "Provider"
	ActionObjectBaseSchema           ActionObject = "BaseSchema"
)

// Predefined action verbs that can be used in actions.
const (
	ActionVerbCreate                 ActionVerb = "Create"
	ActionVerbUpdate                 ActionVerb = "Update"
	ActionVerbDelete                 ActionVerb = "Delete"
	ActionVerbRevoke                 ActionVerb = "Revoke"
	ActionVerbUpdateInfo             ActionVerb = "UpdateInfo"
	ActionVerbUpdatePermissions      ActionVerb = "UpdatePermissions"
	ActionVerbGrantCreate            ActionVerb = "GrantCreate"
	ActionVerbGrantUpdate            ActionVerb = "GrantUpdate"
	ActionVerbGrantDelete            ActionVerb = "GrantDelete"
	ActionVerbGrantRevoke            ActionVerb = "GrantRevoke"
	ActionVerbGrantUpdateInfo        ActionVerb = "GrantUpdateInfo"
	ActionVerbGrantUpdatePermissions ActionVerb = "GrantUpdatePermissions"
)

// Predefined resource objects that can be used in resources.
const (
	ResourceObjectIssuer               ResourceObject = "Issuer"
	ResourceObjectDid                  ResourceObject = "Did"
	ResourceObjectSchema               ResourceObject = "Schema"
	ResourceObjectCredential           ResourceObject = "Credential"
	ResourceObjectPresentation         ResourceObject = "Presentation"
	ResourceObjectAccessibleCredential ResourceObject = "AccessibleCredential"
	ResourceObjectProvider             ResourceObject = "Provider"
	ResourceObjectBaseSchema           ResourceObject = "BaseSchema"
)

// PolicyConstant represents the policy constants used for validation.
// It defines the allowed action objects, action verbs, and resource objects.
type PolicyConstant struct {
	ActionObjects  []ActionObject
	ActionVerbs    []ActionVerb
	ResourceObject []ResourceObject
}

// userConstant is the user-defined policy constant.
// If set by the user via SetCustomConstant(), IsValid() methods will use this
// instead of the default policy constant.
var userConstant *PolicyConstant

// SetCustomConstant sets the global custom constant to be used by IsValid() methods.
// Pass nil to reset to default behavior.
// This allows users to set their own constants once, and all IsValid() calls
// will automatically use it.
func SetCustomConstant(c *PolicyConstant) {
	userConstant = c
}

// getActiveConstant returns the active constant to use for validation.
// Priority: userConstant (if set) > DefaultPolicyConstant()
func getActiveConstant() PolicyConstant {
	if userConstant != nil {
		return *userConstant
	}
	return DefaultPolicyConstant()
}

// OrDefault returns the default policy constant when the receiver is the
// zero-value (i.e. user did not initialize / provide any lists).
func (c PolicyConstant) OrDefault() PolicyConstant {
	if len(c.ActionObjects) == 0 && len(c.ActionVerbs) == 0 && len(c.ResourceObject) == 0 {
		return DefaultPolicyConstant()
	}

	return c
}

// NewPolicyConstant constructs a new policy constant.
func NewPolicyConstant() PolicyConstant {
	return DefaultPolicyConstant()
}

// DefaultPolicyConstant returns the default policy constant with all
// predefined action objects, action verbs, and resource objects.
func DefaultPolicyConstant() PolicyConstant {
	return PolicyConstant{
		ActionObjects: []ActionObject{
			ActionObjectIssuer,
			ActionObjectDid,
			ActionObjectSchema,
			ActionObjectCredential,
			ActionObjectPresentation,
			ActionObjectAccessibleCredential,
			ActionObjectProvider,
			ActionObjectBaseSchema,
		},
		ActionVerbs: []ActionVerb{
			ActionVerbCreate,
			ActionVerbUpdate,
			ActionVerbDelete,
			ActionVerbRevoke,
			ActionVerbUpdateInfo,
			ActionVerbUpdatePermissions,
			ActionVerbGrantCreate,
			ActionVerbGrantUpdate,
			ActionVerbGrantDelete,
			ActionVerbGrantRevoke,
			ActionVerbGrantUpdateInfo,
			ActionVerbGrantUpdatePermissions,
		},
		ResourceObject: []ResourceObject{
			ResourceObjectIssuer,
			ResourceObjectDid,
			ResourceObjectSchema,
			ResourceObjectCredential,
			ResourceObjectPresentation,
			ResourceObjectAccessibleCredential,
			ResourceObjectProvider,
			ResourceObjectBaseSchema,
		},
	}
}

// Get returns a copy of the policy constant.
func (c *PolicyConstant) Get() PolicyConstant {
	return *c
}

// AddActionObject adds an action object to the policy constant.
func (c *PolicyConstant) AddActionObject(object ActionObject) {
	c.ActionObjects = append(c.ActionObjects, object)
}

// AddActionVerb adds an action verb to the policy constant.
func (c *PolicyConstant) AddActionVerb(verb ActionVerb) {
	c.ActionVerbs = append(c.ActionVerbs, verb)
}

// AddResourceObject adds a resource object to the policy constant.
func (c *PolicyConstant) AddResourceObject(object ResourceObject) {
	c.ResourceObject = append(c.ResourceObject, object)
}

// IsValidActionObject checks if the action object is valid according to this constant.
func (c *PolicyConstant) IsValidActionObject(object ActionObject) bool {
	return slices.Contains(c.ActionObjects, object)
}

// IsValidActionVerb checks if the action verb is valid.
func (c *PolicyConstant) IsValidActionVerb(verb ActionVerb) bool {
	return slices.Contains(c.ActionVerbs, verb)
}

// IsValidResourceObject checks if the resource object is valid.
func (c *PolicyConstant) IsValidResourceObject(object ResourceObject) bool {
	return slices.Contains(c.ResourceObject, object)
}
