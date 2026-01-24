package policy

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

// Predefine object and verb used for admin actions and resources.
const (
	AllAction   Action   = "*"
	AllResource Resource = "*"
)

// Predefined effect constants.
const (
	EffectAllow Effect = "allow" // Allow access to the resource.
	EffectDeny  Effect = "deny"  // Deny access to the resource.
)
