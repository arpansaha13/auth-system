// Package middleware provides error handling for HTTP servers
package http

// HTTPErrorHandler converts domain errors to HTTP status codes
type HTTPErrorHandler struct{}

// ErrorToHTTP maps domain errors to HTTP status codes and messages
func (h *HTTPErrorHandler) ErrorToHTTP(err error) (statusCode int, message string) {
	if err == nil {
		return 200, ""
	}

	// Import domain types and map errors
	// This will be implemented based on the domain error types
	return 500, err.Error()
}
