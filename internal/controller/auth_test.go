package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
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

// TestSignupValidation tests request validation for Signup endpoint
func TestSignupValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.SignupRequest
		ExpectedCode  codes.Code
		ExpectedError bool
	}

	testCases := []TestCaseData{
		{
			Name: "Valid signup request",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ExpectedCode:  codes.OK,
			ExpectedError: false,
		},
		{
			Name: "Missing email",
			Request: &pb.SignupRequest{
				Email:    "",
				Password: "securePassword123",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
		{
			Name: "Missing password",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
		{
			Name: "Both fields missing",
			Request: &pb.SignupRequest{
				Email:    "",
				Password: "",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
	}

	mockService := &MockAuthService{
		SignupFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
			return &service.SignupResponse{Message: "success", OTPHash: "test-hash"}, nil
		},
	}

	controller := NewAuthServiceImpl(mockService)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := controller.Signup(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.Equal(t, tc.ExpectedCode, status.Code(err))
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
		ExpectedCode  codes.Code
		ExpectedError bool
	}

	testCases := []TestCaseData{
		{
			Name: "Valid verify OTP request",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "test-hash-12345",
				Code:    "123456",
			},
			ExpectedCode:  codes.OK,
			ExpectedError: false,
		},
		{
			Name: "Missing OTP hash",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "",
				Code:    "123456",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
		{
			Name: "Missing OTP code",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "test-hash-12345",
				Code:    "",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
		{
			Name: "Both fields missing",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "",
				Code:    "",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
	}

	mockService := &MockAuthService{
		VerifyOTPFunc: func(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error) {
			return &service.VerifyOTPResponse{
				Message:      "success",
				Username:     "test_user",
				SessionToken: "token",
				OTPHash:      req.OTPHash,
			}, nil
		},
	}

	controller := NewAuthServiceImpl(mockService)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := controller.VerifyOTP(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.Equal(t, tc.ExpectedCode, status.Code(err))
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
		ExpectedCode  codes.Code
		ExpectedError bool
	}

	testCases := []TestCaseData{
		{
			Name: "Valid login request",
			Request: &pb.LoginRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ExpectedCode:  codes.OK,
			ExpectedError: false,
		},
		{
			Name: "Missing email",
			Request: &pb.LoginRequest{
				Email:    "",
				Password: "securePassword123",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
		{
			Name: "Missing password",
			Request: &pb.LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
		{
			Name: "Both fields missing",
			Request: &pb.LoginRequest{
				Email:    "",
				Password: "",
			},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
	}

	mockService := &MockAuthService{
		LoginFunc: func(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error) {
			return &service.LoginResponse{SessionToken: "token"}, nil
		},
	}

	controller := NewAuthServiceImpl(mockService)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := controller.Login(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.Equal(t, tc.ExpectedCode, status.Code(err))
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotEmpty(t, resp.SessionToken)
			}
		})
	}
}

// TestSignupErrorHandling tests error mapping from service to gRPC
func TestSignupErrorHandling(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.SignupRequest
		ServiceError  error
		ExpectedCode  codes.Code
		ExpectedError bool
	}

	testCases := []TestCaseData{
		{
			Name: "Service returns conflict error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &domain.ConflictError{Message: "email already registered"},
			ExpectedCode:  codes.AlreadyExists,
			ExpectedError: true,
		},
		{
			Name: "Service returns validation error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &domain.ValidationError{Message: "invalid email format", Field: "email"},
			ExpectedCode:  codes.InvalidArgument,
			ExpectedError: true,
		},
		{
			Name: "Service returns internal error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &domain.InternalError{Message: "database error"},
			ExpectedCode:  codes.Internal,
			ExpectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthService{
				SignupFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
					return nil, tc.ServiceError
				},
			}

			controller := NewAuthServiceImpl(mockService)
			resp, err := controller.Signup(context.Background(), tc.Request)

			require.Error(t, err)
			assert.Equal(t, tc.ExpectedCode, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}
