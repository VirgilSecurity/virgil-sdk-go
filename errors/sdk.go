package errors

// HTTPError stores HTTP Status error.
type HTTPError struct {
	code int
}

// GetCode gets HTTP status code.
func (httpError HTTPError) HTTPErrorCode() int {
	return httpError.code
}

// ServiceError stores Service errors.
type ServiceError struct {
	code int
}

// GetCode gets Service error code.
func (serviceError ServiceError) ServiceErrorCode() int {
	return serviceError.code
}

type SDKError struct {
	HTTPError
	ServiceError
	Message string
}

func (e *SDKError) Error() string {
	return e.Message
}

// IsHTTPError checks if an error is HTTP status code based error.
func (e *SDKError) IsHTTPError() bool {
	return e.HTTPError.code != 0
}

// IsServiceError checks if an error is Service error.
func (e *SDKError) IsServiceError() bool {
	return e.ServiceError.code != 0
}

// New returns an error that formats as the given text.
func New(message string) error {
	return &SDKError{
		Message: message,
	}
}

// NewServiceError returns an Service error.
func NewServiceError(serviceErrorCode int, httpCode int, message string) error {
	return &SDKError{
		Message: message,
		ServiceError: ServiceError{
			code: serviceErrorCode,
		},
		HTTPError: HTTPError{
			code: httpCode,
		},
	}
}

// NewHttpError returns an error based on HTTP status code.
func NewHttpError(httpCode int, message string) error {
	return &SDKError{
		Message: message,
		HTTPError: HTTPError{
			code: httpCode,
		},
	}
}

func ToSdkError(err error) (*SDKError, bool) {
	e, ok := Cause(err).(*SDKError)
	return e, ok
}
