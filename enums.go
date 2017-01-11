package virgil

type Enum string

const (
	unspecified = "unspecified"
	compromised = "compromised"
	application = "application"
	global      = "global"
)

var (
	CardScope struct {
		Application, Global Enum
	}
	RevocationReason struct {
		Unspecified, Compromised Enum
	}
)

func init() {
	CardScope.Application = application
	CardScope.Global = global

	RevocationReason.Unspecified = unspecified
	RevocationReason.Compromised = compromised
}
