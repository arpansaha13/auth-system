// Package controller provides gRPC controllers for goauthkit
package grpc

import (
	ictl "github.com/arpansaha13/goauthkit/internal/controller"
	"github.com/arpansaha13/goauthkit/pkg/service"
	"github.com/arpansaha13/goauthkit/pkg/utils"
)

// Controller implementations
type AuthServiceImpl = ictl.AuthServiceImpl

// Constructors
func NewAuthServiceImpl(authService service.IAuthService, validator *utils.Validator) *AuthServiceImpl {
	return ictl.NewAuthServiceImpl(authService, validator)
}
