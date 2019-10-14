package pythia

type Error struct {
	Code int
	Message string
}

func NewPythiaError(code int, message string) Error{
	return Error{Code:code, Message: message}
}

func (e Error) Error() string{
	return e.Message
}

