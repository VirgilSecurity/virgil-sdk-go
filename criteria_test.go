package virgil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchCriteriaByIdentities_CheckStruct(t *testing.T) {
	expected := Criteria{
		Identities: []string{
			"Test1",
			"Test2",
		},
		Scope: CardScope.Application,
	}
	actual := SearchCriteriaByIdentities("Test1", "Test2")

	assert.Equal(t, expected, actual)
}

func TestSearchCriteriaByAppBundle_CheckStruct(t *testing.T) {
	expected := Criteria{
		Identities: []string{
			"Test1",
			"Test2",
		},
		Scope:        CardScope.Global,
		IdentityType: "application",
	}
	actual := SearchCriteriaByAppBundle("Test1", "Test2")

	assert.Equal(t, expected, actual)
}
