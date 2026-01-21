package controller

import (
	"context"
	"fmt"
	"log"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuthServiceImpl implements the gRPC AuthService
type AuthServiceImpl struct {
	pb.UnimplementedAuthServiceServer
	authService service.IAuthService
}

// NewAuthServiceImpl creates a new auth service implementation
func NewAuthServiceImpl(authService service.IAuthService) *AuthServiceImpl {
	return &AuthServiceImpl{
		authService: authService,
	}
}

// Signup handles user registration
func (s *AuthServiceImpl) Signup(ctx context.Context, req *pb.SignupRequest) (*pb.SignupResponse, error) {
	// Validate request
	if err := validateSignupRequest(req); err != nil {
		log.Printf("signup validation error: %v", err)
		return nil, errorToGRPCError(err)
	}

	// Call service
	serviceReq := service.SignupRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := s.authService.Signup(ctx, serviceReq)
	if err != nil {
		log.Printf("signup error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.SignupResponse{
		Message: resp.Message,
		OtpHash: resp.OTPHash,
	}, nil
}

// VerifyOTP verifies an OTP and marks user as verified
func (s *AuthServiceImpl) VerifyOTP(ctx context.Context, req *pb.VerifyOTPRequest) (*pb.VerifyOTPResponse, error) {
	// Validate request
	if err := validateVerifyOTPRequest(req); err != nil {
		log.Printf("verify otp validation error: %v", err)
		return nil, errorToGRPCError(err)
	}

	// Call service
	serviceReq := service.VerifyOTPRequest{
		OTPHash: req.OtpHash,
		Code:    req.Code,
	}

	resp, err := s.authService.VerifyOTP(ctx, serviceReq)
	if err != nil {
		log.Printf("verify otp error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.VerifyOTPResponse{
		Message:      resp.Message,
		Username:     resp.Username,
		SessionToken: resp.SessionToken,
	}, nil
}

// Login authenticates a user
func (s *AuthServiceImpl) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Validate request
	if err := validateLoginRequest(req); err != nil {
		log.Printf("login validation error: %v", err)
		return nil, errorToGRPCError(err)
	}

	// Call service
	serviceReq := service.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := s.authService.Login(ctx, serviceReq)
	if err != nil {
		log.Printf("login error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.LoginResponse{
		SessionToken: resp.SessionToken,
		ExpiresAt:    timestamppb.New(resp.ExpiresAt),
	}, nil
}

// ValidateSession validates a session token
func (s *AuthServiceImpl) ValidateSession(ctx context.Context, req *pb.ValidateSessionRequest) (*pb.ValidateSessionResponse, error) {
	// Extract token from metadata
	token := extractToken(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	// Call service
	serviceReq := service.ValidateSessionRequest{
		Token: token,
	}

	resp, err := s.authService.ValidateSession(ctx, serviceReq)
	if err != nil {
		log.Printf("validate session error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.ValidateSessionResponse{
		UserId: resp.UserID,
		Valid:  resp.Valid,
	}, nil
}

// RefreshSession extends a valid session
func (s *AuthServiceImpl) RefreshSession(ctx context.Context, req *pb.RefreshSessionRequest) (*pb.RefreshSessionResponse, error) {
	// Extract token from metadata
	token := extractToken(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	// Call service
	serviceReq := service.RefreshSessionRequest{
		Token: token,
	}

	resp, err := s.authService.RefreshSession(ctx, serviceReq)
	if err != nil {
		log.Printf("refresh session error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.RefreshSessionResponse{
		NewSessionToken: resp.NewSessionToken,
	}, nil
}

// Logout logs out a session
func (s *AuthServiceImpl) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	// Extract token from metadata
	token := extractToken(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	// Call service
	serviceReq := service.LogoutRequest{
		Token: token,
	}

	resp, err := s.authService.Logout(ctx, serviceReq)
	if err != nil {
		log.Printf("logout error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.LogoutResponse{
		Message: resp.Message,
	}, nil
}

// ForgotPassword initiates password reset by sending OTP to email
func (s *AuthServiceImpl) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest) (*pb.ForgotPasswordResponse, error) {
	// Validate request
	if err := validateForgotPasswordRequest(req); err != nil {
		log.Printf("forgot password validation error: %v", err)
		return nil, errorToGRPCError(err)
	}

	// Call service
	serviceReq := service.ForgotPasswordRequest{
		Email: req.Email,
	}

	resp, err := s.authService.ForgotPassword(ctx, serviceReq)
	if err != nil {
		log.Printf("forgot password error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.ForgotPasswordResponse{
		Message: resp.Message,
		OtpHash: resp.OTPHash,
	}, nil
}

// ResetPassword verifies OTP and resets user's password
func (s *AuthServiceImpl) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	// Validate request
	if err := validateResetPasswordRequest(req); err != nil {
		log.Printf("reset password validation error: %v", err)
		return nil, errorToGRPCError(err)
	}

	// Call service
	serviceReq := service.ResetPasswordRequest{
		OTPHash:  req.OtpHash,
		Code:     req.Code,
		Password: req.Password,
	}

	resp, err := s.authService.ResetPassword(ctx, serviceReq)
	if err != nil {
		log.Printf("reset password error: %v", err)
		return nil, errorToGRPCError(err)
	}

	return &pb.ResetPasswordResponse{
		Message: resp.Message,
	}, nil
}

// Private helper and validation functions

func validateSignupRequest(req *pb.SignupRequest) error {
	if req.Email == "" {
		return &domain.ValidationError{Message: "email is required", Field: "email"}
	}
	if req.Password == "" {
		return &domain.ValidationError{Message: "password is required", Field: "password"}
	}
	return nil
}

func validateVerifyOTPRequest(req *pb.VerifyOTPRequest) error {
	if req.OtpHash == "" {
		return &domain.ValidationError{Message: "otp_hash is required", Field: "otp_hash"}
	}
	if req.Code == "" {
		return &domain.ValidationError{Message: "code is required", Field: "code"}
	}
	return nil
}

func validateLoginRequest(req *pb.LoginRequest) error {
	if req.Email == "" {
		return &domain.ValidationError{Message: "email is required", Field: "email"}
	}
	if req.Password == "" {
		return &domain.ValidationError{Message: "password is required", Field: "password"}
	}
	return nil
}

func validateForgotPasswordRequest(req *pb.ForgotPasswordRequest) error {
	if req.Email == "" {
		return &domain.ValidationError{Message: "email is required", Field: "email"}
	}
	return nil
}

func validateResetPasswordRequest(req *pb.ResetPasswordRequest) error {
	if req.OtpHash == "" {
		return &domain.ValidationError{Message: "otp_hash is required", Field: "otp_hash"}
	}
	if req.Code == "" {
		return &domain.ValidationError{Message: "code is required", Field: "code"}
	}
	if req.Password == "" {
		return &domain.ValidationError{Message: "password is required", Field: "password"}
	}
	return nil
}

func extractToken(ctx context.Context) string {
	// Extract from context metadata
	// This will be populated by the interceptor
	token, ok := ctx.Value("authorization").(string)
	if !ok {
		return ""
	}
	return token
}

func errorToGRPCError(err error) error {
	if err == nil {
		return nil
	}

	// Check error types and map to appropriate gRPC codes
	if domain.IsValidation(err) {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	if domain.IsConflict(err) {
		return status.Error(codes.AlreadyExists, err.Error())
	}

	if domain.IsNotFound(err) {
		return status.Error(codes.NotFound, err.Error())
	}

	if domain.IsUnauthorized(err) {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	// Default to internal error
	return status.Error(codes.Internal, fmt.Sprintf("internal server error: %v", err))
}
