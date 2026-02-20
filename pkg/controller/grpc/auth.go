// Package controller provides gRPC controllers for auth-system
package grpc

import (
	ictl "github.com/arpansaha13/auth-system/internal/controller"
	"github.com/arpansaha13/auth-system/pkg/service"
	"github.com/arpansaha13/auth-system/pkg/utils"
)

// Controller implementations
type AuthServiceImpl = ictl.AuthServiceImpl

// Constructors
func NewAuthServiceImpl(authService service.IAuthService, validator *utils.Validator) *AuthServiceImpl {
	return ictl.NewAuthServiceImpl(authService, validator)
}
