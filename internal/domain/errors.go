package domain

import "fmt"

// Custom error types for the auth system

// ValidationError represents validation failures
type ValidationError struct {
	Message string
	Field   string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error on field %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// ConflictError represents resource conflict (e.g., duplicate email)
type ConflictError struct {
	Message string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict: %s", e.Message)
}

// NotFoundError represents missing resource
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("not found: %s", e.Message)
}

// UnauthorizedError represents authentication failures
type UnauthorizedError struct {
	Message string
}

func (e *UnauthorizedError) Error() string {
	return fmt.Sprintf("unauthorized: %s", e.Message)
}

// InternalError represents unexpected server errors
type InternalError struct {
	Message string
	Err     error
}

func (e *InternalError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("internal error: %s - %v", e.Message, e.Err)
	}
	return fmt.Sprintf("internal error: %s", e.Message)
}

// IsConflict checks if an error is a ConflictError
func IsConflict(err error) bool {
	_, ok := err.(*ConflictError)
	return ok
}

// IsNotFound checks if an error is a NotFoundError
func IsNotFound(err error) bool {
	_, ok := err.(*NotFoundError)
	return ok
}

// IsUnauthorized checks if an error is an UnauthorizedError
func IsUnauthorized(err error) bool {
	_, ok := err.(*UnauthorizedError)
	return ok
}

// IsValidation checks if an error is a ValidationError
func IsValidation(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}
