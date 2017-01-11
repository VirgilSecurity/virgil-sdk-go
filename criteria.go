package virgil

type Criteria struct {
	Scope        Enum     `json:"scope,omitempty"`
	IdentityType string   `json:"indentity_type,omitempty"`
	Identities   []string `json:"identities"`
}

// SearchCriteriaByIdentities create search criteria by identities in application scope
//
func SearchCriteriaByIdentities(identites ...string) Criteria {
	return Criteria{
		Scope:      CardScope.Application,
		Identities: identites,
	}
}

// SearchCriteriaByAppBundle create search criteria by bundle name in global scope
//
func SearchCriteriaByAppBundle(bundle ...string) Criteria {
	return Criteria{
		Scope:        CardScope.Global,
		Identities:   bundle,
		IdentityType: "application",
	}
}
