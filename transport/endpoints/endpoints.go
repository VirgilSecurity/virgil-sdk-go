package endpoints

type Endpoint int

const (
	GetCard Endpoint = iota
	SearchCards
	CreateCard
	RevokeCard
	VerifyIdentity
	ConfirmIdentity
	ValidateIdentity
)
