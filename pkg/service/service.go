// Package service re-exports auth system services
package service

import (
	irepo "github.com/arpansaha13/goauthkit/internal/repository"
	isvc "github.com/arpansaha13/goauthkit/internal/service"
	iutil "github.com/arpansaha13/goauthkit/internal/utils"
)

// Interfaces
type IAuthService = isvc.IAuthService

// Service implementations
type AuthService = isvc.AuthService
type AuthServiceConfig = isvc.AuthServiceConfig

// Request/Response types
type SignupRequest = isvc.SignupRequest
type SignupResponse = isvc.SignupResponse
type VerifyOTPRequest = isvc.VerifyOTPRequest
type VerifyOTPResponse = isvc.VerifyOTPResponse
type LoginRequest = isvc.LoginRequest
type LoginResponse = isvc.LoginResponse
type ValidateSessionRequest = isvc.ValidateSessionRequest
type ValidateSessionResponse = isvc.ValidateSessionResponse
type RefreshSessionRequest = isvc.RefreshSessionRequest
type RefreshSessionResponse = isvc.RefreshSessionResponse
type LogoutRequest = isvc.LogoutRequest
type LogoutResponse = isvc.LogoutResponse
type ForgotPasswordRequest = isvc.ForgotPasswordRequest
type ForgotPasswordResponse = isvc.ForgotPasswordResponse
type ResetPasswordRequest = isvc.ResetPasswordRequest
type ResetPasswordResponse = isvc.ResetPasswordResponse
type GetUserRequest = isvc.GetUserRequest
type GetUserResponse = isvc.GetUserResponse
type GetUserByEmailRequest = isvc.GetUserByEmailRequest
type GetUserByEmailResponse = isvc.GetUserByEmailResponse
type DeleteUserRequest = isvc.DeleteUserRequest
type DeleteUserResponse = isvc.DeleteUserResponse

// Constructors
func NewAuthService(
	userRepo irepo.IUserRepository,
	otpRepo irepo.IOTPRepository,
	sessionRepo irepo.ISessionRepository,
	hasher *iutil.PasswordHasher,
	config AuthServiceConfig,
) IAuthService {
	return isvc.NewAuthService(userRepo, otpRepo, sessionRepo, hasher, config)
}
