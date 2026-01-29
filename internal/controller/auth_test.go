package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/pb"
)

// MockAuthService mocks the auth service for controller tests
type MockAuthService struct {
	SignupFunc          func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error)
	VerifyOTPFunc       func(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error)
	LoginFunc           func(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error)
	ValidateSessionFunc func(ctx context.Context, req service.ValidateSessionRequest) (*service.ValidateSessionResponse, error)
	RefreshSessionFunc  func(ctx context.Context, req service.RefreshSessionRequest) (*service.RefreshSessionResponse, error)
	LogoutFunc          func(ctx context.Context, req service.LogoutRequest) (*service.LogoutResponse, error)
	ForgotPasswordFunc  func(ctx context.Context, req service.ForgotPasswordRequest) (*service.ForgotPasswordResponse, error)
	ResetPasswordFunc   func(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error)
	GetUserFunc         func(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error)
	GetUserByEmailFunc  func(ctx context.Context, req service.GetUserByEmailRequest) (*service.GetUserByEmailResponse, error)
	DeleteUserFunc      func(ctx context.Context, req service.DeleteUserRequest) (*service.DeleteUserResponse, error)
}

func (m *MockAuthService) Signup(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
	if m.SignupFunc != nil {
		return m.SignupFunc(ctx, req)
	}
	return &service.SignupResponse{Message: "success", OTPHash: "test-hash"}, nil
}

func (m *MockAuthService) VerifyOTP(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error) {
	if m.VerifyOTPFunc != nil {
		return m.VerifyOTPFunc(ctx, req)
	}
	return &service.VerifyOTPResponse{Message: "success", Username: "test_user", SessionToken: "token"}, nil
}

func (m *MockAuthService) Login(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, req)
	}
	return &service.LoginResponse{SessionToken: "token"}, nil
}

func (m *MockAuthService) ValidateSession(ctx context.Context, req service.ValidateSessionRequest) (*service.ValidateSessionResponse, error) {
	if m.ValidateSessionFunc != nil {
		return m.ValidateSessionFunc(ctx, req)
	}
	return &service.ValidateSessionResponse{Valid: true, UserID: 1}, nil
}

func (m *MockAuthService) RefreshSession(ctx context.Context, req service.RefreshSessionRequest) (*service.RefreshSessionResponse, error) {
	if m.RefreshSessionFunc != nil {
		return m.RefreshSessionFunc(ctx, req)
	}
	return &service.RefreshSessionResponse{NewSessionToken: "new-token"}, nil
}

func (m *MockAuthService) Logout(ctx context.Context, req service.LogoutRequest) (*service.LogoutResponse, error) {
	if m.LogoutFunc != nil {
		return m.LogoutFunc(ctx, req)
	}
	return &service.LogoutResponse{Message: "logout successful"}, nil
}

func (m *MockAuthService) ForgotPassword(ctx context.Context, req service.ForgotPasswordRequest) (*service.ForgotPasswordResponse, error) {
	if m.ForgotPasswordFunc != nil {
		return m.ForgotPasswordFunc(ctx, req)
	}
	return &service.ForgotPasswordResponse{Message: "if email exists, reset link will be sent", OTPHash: "test-hash"}, nil
}

func (m *MockAuthService) ResetPassword(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error) {
	if m.ResetPasswordFunc != nil {
		return m.ResetPasswordFunc(ctx, req)
	}
	return &service.ResetPasswordResponse{Message: "password reset successfully"}, nil
}

func (m *MockAuthService) GetUser(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error) {
	if m.GetUserFunc != nil {
		return m.GetUserFunc(ctx, req)
	}
	return &service.GetUserResponse{
		User: service.UserData{
			UserID:   1,
			Email:    "test@example.com",
			Username: "test_user",
		},
	}, nil
}

func (m *MockAuthService) GetUserByEmail(ctx context.Context, req service.GetUserByEmailRequest) (*service.GetUserByEmailResponse, error) {
	if m.GetUserByEmailFunc != nil {
		return m.GetUserByEmailFunc(ctx, req)
	}
	return &service.GetUserByEmailResponse{
		User: service.UserData{
			UserID:   1,
			Email:    req.Email,
			Username: "test_user",
		},
	}, nil
}

func (m *MockAuthService) DeleteUser(ctx context.Context, req service.DeleteUserRequest) (*service.DeleteUserResponse, error) {
	if m.DeleteUserFunc != nil {
		return m.DeleteUserFunc(ctx, req)
	}
	return &service.DeleteUserResponse{Message: "user deleted successfully"}, nil
}

// newTestController creates a new AuthServiceImpl with a real validator for testing
func newTestController(mockService service.IAuthService) *AuthServiceImpl {
	validator := utils.NewValidator()
	return NewAuthServiceImpl(mockService, validator)
}

// TestSignupValidation tests request validation for Signup endpoint
func TestSignupValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.SignupRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid signup request",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return &service.SignupResponse{Message: "success", OTPHash: "test-hash"}, nil
			},
		},
		{
			Name: "Missing email",
			Request: &pb.SignupRequest{
				Email:    "",
				Password: "securePassword123",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Missing password",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Both fields missing",
			Request: &pb.SignupRequest{
				Email:    "",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthService{
				SignupFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.Signup(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, "success", resp.Message)
				assert.Equal(t, "test-hash", resp.OtpHash)
			}
		})
	}
}

// TestVerifyOTPValidation tests request validation for VerifyOTP endpoint
func TestVerifyOTPValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.VerifyOTPRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid verify OTP request",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "test-hash-12345",
				Code:    "123456",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error) {
				return &service.VerifyOTPResponse{
					Message:      "success",
					Username:     "test_user",
					SessionToken: "token",
					OTPHash:      req.OTPHash,
				}, nil
			},
		},
		{
			Name: "Missing OTP hash",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "",
				Code:    "123456",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Missing OTP code",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "test-hash-12345",
				Code:    "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Both fields missing",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "",
				Code:    "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthService{
				VerifyOTPFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.VerifyOTP(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, "success", resp.Message)
				assert.Equal(t, "test_user", resp.Username)
				assert.NotEmpty(t, resp.SessionToken)
			}
		})
	}
}

// TestLoginValidation tests request validation for Login endpoint
func TestLoginValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.LoginRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid login request",
			Request: &pb.LoginRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error) {
				return &service.LoginResponse{SessionToken: "token"}, nil
			},
		},
		{
			Name: "Missing email",
			Request: &pb.LoginRequest{
				Email:    "",
				Password: "securePassword123",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Missing password",
			Request: &pb.LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Both fields missing",
			Request: &pb.LoginRequest{
				Email:    "",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthService{
				LoginFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.Login(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotEmpty(t, resp.SessionToken)
			}
		})
	}
}

// TestSignupErrorHandling tests error handling for Signup endpoint
func TestSignupErrorHandling(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.SignupRequest
		ServiceError  error
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Service returns conflict error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &domain.ConflictError{Message: "email already registered"},
			ExpectedError: true,
			ErrorType:     (*domain.ConflictError)(nil),
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return nil, &domain.ConflictError{Message: "email already registered"}
			},
		},
		{
			Name: "Service returns validation error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &domain.ValidationError{Message: "invalid email format", Field: "email"},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return nil, &domain.ValidationError{Message: "invalid email format", Field: "email"}
			},
		},
		{
			Name: "Service returns internal error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &domain.InternalError{Message: "database error"},
			ExpectedError: true,
			ErrorType:     (*domain.InternalError)(nil),
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return nil, &domain.InternalError{Message: "database error"}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthService{
				SignupFunc: tc.MockFunc,
			}

			controller := newTestController(mockService)
			resp, err := controller.Signup(context.Background(), tc.Request)

			require.Error(t, err)
			assert.IsType(t, tc.ErrorType, err)
			assert.Nil(t, resp)
		})
	}
}

// TestForgotPasswordValidation tests request validation for ForgotPassword endpoint
func TestForgotPasswordValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.ForgotPasswordRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.ForgotPasswordRequest) (*service.ForgotPasswordResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid forgot password request",
			Request: &pb.ForgotPasswordRequest{
				Email: "user@example.com",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.ForgotPasswordRequest) (*service.ForgotPasswordResponse, error) {
				return &service.ForgotPasswordResponse{
					Message: "if email exists, reset link will be sent",
					OTPHash: "test-hash",
				}, nil
			},
		},
		{
			Name: "Empty email",
			Request: &pb.ForgotPasswordRequest{
				Email: "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthService{
				ForgotPasswordFunc: tc.MockFunc,
			}

			controller := newTestController(mockService)
			resp, err := controller.ForgotPassword(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}

// TestResetPasswordValidation tests request validation for ResetPassword endpoint
func TestResetPasswordValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.ResetPasswordRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid reset password request",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "test-hash",
				Code:     "123456",
				Password: "newPassword123",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error) {
				return &service.ResetPasswordResponse{
					Message: "password reset successfully",
				}, nil
			},
		},
		{
			Name: "Empty OTP hash",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "",
				Code:     "123456",
				Password: "newPassword123",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Invalid OTP code format",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "test-hash",
				Code:     "12345", // Too short
				Password: "newPassword123",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Password too short",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "test-hash",
				Code:     "123456",
				Password: "short", // Less than 8 characters
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Unauthorized - invalid OTP",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "invalid-hash",
				Code:     "123456",
				Password: "newPassword123",
			},
			ExpectedError: true,
			ErrorType:     (*domain.UnauthorizedError)(nil),
			MockFunc: func(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error) {
				return nil, &domain.UnauthorizedError{Message: "invalid otp code"}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthService{
				ResetPasswordFunc: tc.MockFunc,
			}

			controller := newTestController(mockService)
			resp, err := controller.ResetPassword(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}
