package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/pb"
)

// MockAuthServiceForUser mocks the auth service for user controller tests
type MockAuthServiceForUser struct {
	GetUserFunc        func(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error)
	GetUserByEmailFunc func(ctx context.Context, req service.GetUserByEmailRequest) (*service.GetUserByEmailResponse, error)
	DeleteUserFunc     func(ctx context.Context, req service.DeleteUserRequest) (*service.DeleteUserResponse, error)
}

// Implement the IAuthService interface for mocking
func (m *MockAuthServiceForUser) Signup(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) VerifyOTP(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) Login(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) ValidateSession(ctx context.Context, req service.ValidateSessionRequest) (*service.ValidateSessionResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) RefreshSession(ctx context.Context, req service.RefreshSessionRequest) (*service.RefreshSessionResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) Logout(ctx context.Context, req service.LogoutRequest) (*service.LogoutResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) ForgotPassword(ctx context.Context, req service.ForgotPasswordRequest) (*service.ForgotPasswordResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) ResetPassword(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForUser) GetUser(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error) {
	if m.GetUserFunc != nil {
		return m.GetUserFunc(ctx, req)
	}
	return &service.GetUserResponse{
		User: service.UserData{
			UserID:   1,
			Email:    "test@example.com",
			Username: "test_user",
			Verified: true,
		},
	}, nil
}

func (m *MockAuthServiceForUser) GetUserByEmail(ctx context.Context, req service.GetUserByEmailRequest) (*service.GetUserByEmailResponse, error) {
	if m.GetUserByEmailFunc != nil {
		return m.GetUserByEmailFunc(ctx, req)
	}
	return &service.GetUserByEmailResponse{
		User: service.UserData{
			UserID:   1,
			Email:    req.Email,
			Username: "test_user",
			Verified: true,
		},
	}, nil
}

func (m *MockAuthServiceForUser) DeleteUser(ctx context.Context, req service.DeleteUserRequest) (*service.DeleteUserResponse, error) {
	if m.DeleteUserFunc != nil {
		return m.DeleteUserFunc(ctx, req)
	}
	return &service.DeleteUserResponse{Message: "user deleted successfully"}, nil
}

// TestGetUserValidation tests request validation for GetUser endpoint
func TestGetUserValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.GetUserRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid get user request",
			Request: &pb.GetUserRequest{
				UserId: 1,
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error) {
				return &service.GetUserResponse{
					User: service.UserData{
						UserID:   req.UserID,
						Email:    "test@example.com",
						Username: "test_user",
					},
				}, nil
			},
		},
		{
			Name: "User ID is zero",
			Request: &pb.GetUserRequest{
				UserId: 0,
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Negative user ID",
			Request: &pb.GetUserRequest{
				UserId: -1,
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthServiceForUser{
				GetUserFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.GetUser(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotNil(t, resp.User)
			}
		})
	}
}

// TestGetUserByEmailValidation tests request validation for GetUserByEmail endpoint
func TestGetUserByEmailValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.GetUserByEmailRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.GetUserByEmailRequest) (*service.GetUserByEmailResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid get user by email request",
			Request: &pb.GetUserByEmailRequest{
				Email: "test@example.com",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.GetUserByEmailRequest) (*service.GetUserByEmailResponse, error) {
				return &service.GetUserByEmailResponse{
					User: service.UserData{
						UserID:   1,
						Email:    req.Email,
						Username: "test_user",
					},
				}, nil
			},
		},
		{
			Name: "Missing email",
			Request: &pb.GetUserByEmailRequest{
				Email: "",
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthServiceForUser{
				GetUserByEmailFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.GetUserByEmail(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotNil(t, resp.User)
			}
		})
	}
}

// TestDeleteUserValidation tests request validation for DeleteUser endpoint
func TestDeleteUserValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.DeleteUserRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.DeleteUserRequest) (*service.DeleteUserResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid delete user request",
			Request: &pb.DeleteUserRequest{
				UserId: 1,
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.DeleteUserRequest) (*service.DeleteUserResponse, error) {
				return &service.DeleteUserResponse{Message: "user deleted successfully"}, nil
			},
		},
		{
			Name: "User ID is zero",
			Request: &pb.DeleteUserRequest{
				UserId: 0,
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
		{
			Name: "Negative user ID",
			Request: &pb.DeleteUserRequest{
				UserId: -1,
			},
			ExpectedError: true,
			ErrorType:     (*domain.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthServiceForUser{
				DeleteUserFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.DeleteUser(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, "user deleted successfully", resp.Message)
			}
		})
	}
}

// TestGetUserErrorHandling tests error handling for GetUser endpoint
func TestGetUserErrorHandling(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.GetUserRequest
		ServiceError  error
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "User not found error",
			Request: &pb.GetUserRequest{
				UserId: 999,
			},
			ServiceError:  &domain.NotFoundError{Message: "user not found"},
			ExpectedError: true,
			ErrorType:     (*domain.NotFoundError)(nil),
			MockFunc: func(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error) {
				return nil, &domain.NotFoundError{Message: "user not found"}
			},
		},
		{
			Name: "Internal server error",
			Request: &pb.GetUserRequest{
				UserId: 1,
			},
			ServiceError:  &domain.InternalError{Message: "database connection failed"},
			ExpectedError: true,
			ErrorType:     (*domain.InternalError)(nil),
			MockFunc: func(ctx context.Context, req service.GetUserRequest) (*service.GetUserResponse, error) {
				return nil, &domain.InternalError{Message: "database connection failed"}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &MockAuthServiceForUser{
				GetUserFunc: tc.MockFunc,
			}

			controller := newTestController(mockService)
			resp, err := controller.GetUser(context.Background(), tc.Request)

			require.Error(t, err)
			assert.IsType(t, tc.ErrorType, err)
			assert.Nil(t, resp)
		})
	}
}
