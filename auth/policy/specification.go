package policy

// Specification represents a list of action objects, action verbs, and resource objects that are allowed to construct permission statements.
type Specification struct {
	ActionObjects   []ActionObject   `json:"actionObjects"`
	ActionVerbs     []ActionVerb     `json:"actionVerbs"`
	ResourceObjects []ResourceObject `json:"resourceObjects"`
}

// NewSpecification constructs a Specification from the given action objects, action verbs, and resource objects.
func NewSpecification(actionObjects []ActionObject, actionVerbs []ActionVerb, resourceObjects []ResourceObject) Specification {
	return Specification{
		ActionObjects:   actionObjects,
		ActionVerbs:     actionVerbs,
		ResourceObjects: resourceObjects,
	}
}

// DefaultSpecification constructs a Specification with the default action objects, action verbs, and resource objects.
func DefaultSpecification() Specification {
	return Specification{
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
		ResourceObjects: []ResourceObject{
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
