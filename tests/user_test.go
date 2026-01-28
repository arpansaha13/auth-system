package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/pb"
)

// TestGetUserEndpoint tests the GetUser gRPC endpoint
func TestGetUser(t *testing.T) {
	testOTPCode := "123456"

	tests := []TableDrivenTestCase{
		{
			Name: "Get existing user by user ID",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()
				hasher := utils.NewPasswordHasher()

				// Create and verify a test user
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "getuser@example.com",
					Password: "password123",
				})
				if err != nil {
					return err
				}

				otpHashCode, _ := hasher.Hash(testOTPCode)
				if err := f.TestDB.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", signupResp.OTPHash).
					Update("hashed_code", otpHashCode).Error; err != nil {
					return err
				}

				_, err = authService.VerifyOTP(f.Ctx, service.VerifyOTPRequest{
					OTPHash: signupResp.OTPHash,
					Code:    testOTPCode,
				})
				return err
			},
			Test: func(f *TestFixture) error {
				// Get a valid session
				var session domain.Session
				require.NoError(f.T, f.TestDB.DB.Where("deleted_at IS NULL").First(&session).Error)

				// Get the user
				var user domain.User
				require.NoError(f.T, f.TestDB.DB.Where("id = ?", session.UserID).First(&user).Error)

				// Add token to context
				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				resp, err := f.GRPCClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: int64(user.ID)})

				require.NoError(f.T, err)
				require.NotNil(f.T, resp.User, "expected user in response")
				require.Equal(f.T, "getuser@example.com", resp.User.Email, "email mismatch")
				require.True(f.T, resp.User.Verified, "expected user to be verified")
				return nil
			},
			ExpectError: false,
		},
		{
			Name: "Get non-existent user returns error",
			Setup: func(f *TestFixture) error {
				return nil
			},
			Test: func(f *TestFixture) error {
				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				resp, err := f.GRPCClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: 99999})

				// We expect an error for non-existent user
				require.Error(f.T, err, "expected error for non-existent user")
				// If we got an error as expected, that's success
				require.Nil(f.T, resp)
				return nil
			},
			ExpectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			fixture := NewTestFixture(t)
			fixture.Setup()

			if err := tt.Setup(fixture); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			err := tt.Test(fixture)
			if (err != nil) != tt.ExpectError {
				t.Errorf("test failed: got error %v, want error %v", err, tt.ExpectError)
			}

			if tt.Verify != nil {
				if err := tt.Verify(fixture); err != nil {
					t.Errorf("verification failed: %v", err)
				}
			}
		})
	}
}

// TestGetUserByEmailEndpoint tests the GetUserByEmail gRPC endpoint
func TestGetUserByEmail(t *testing.T) {
	testOTPCode := "123456"

	tests := []TableDrivenTestCase{
		{
			Name: "Get user by existing email",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()
				hasher := utils.NewPasswordHasher()

				// Create and verify a test user
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "getuserbyemail@example.com",
					Password: "password123",
				})
				if err != nil {
					return err
				}

				otpHashCode, _ := hasher.Hash(testOTPCode)
				if err := f.TestDB.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", signupResp.OTPHash).
					Update("hashed_code", otpHashCode).Error; err != nil {
					return err
				}

				_, err = authService.VerifyOTP(f.Ctx, service.VerifyOTPRequest{
					OTPHash: signupResp.OTPHash,
					Code:    testOTPCode,
				})
				return err
			},
			Test: func(f *TestFixture) error {
				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				resp, err := f.GRPCClient.GetUserByEmail(ctxWithToken, &pb.GetUserByEmailRequest{Email: "getuserbyemail@example.com"})

				require.NoError(f.T, err)
				require.NotNil(f.T, resp.User, "expected user in response")
				require.Equal(f.T, "getuserbyemail@example.com", resp.User.Email, "email mismatch")
				require.True(f.T, resp.User.Verified, "expected user to be verified")
				return nil
			},
			ExpectError: false,
		},
		{
			Name: "Get user by non-existent email returns error",
			Setup: func(f *TestFixture) error {
				return nil
			},
			Test: func(f *TestFixture) error {
				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				resp, err := f.GRPCClient.GetUserByEmail(ctxWithToken, &pb.GetUserByEmailRequest{Email: "nonexistent@example.com"})

				// We expect an error for non-existent email
				require.Error(f.T, err, "expected error for non-existent email")
				// If we got an error as expected, that's success
				require.Nil(f.T, resp)
				return nil
			},
			ExpectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			fixture := NewTestFixture(t)
			fixture.Setup()

			if err := tt.Setup(fixture); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			err := tt.Test(fixture)
			if (err != nil) != tt.ExpectError {
				t.Errorf("test failed: got error %v, want error %v", err, tt.ExpectError)
			}

			if tt.Verify != nil {
				if err := tt.Verify(fixture); err != nil {
					t.Errorf("verification failed: %v", err)
				}
			}
		})
	}
}

// TestDeleteUserEndpoint tests the DeleteUser gRPC endpoint
func TestDeleteUser(t *testing.T) {
	testOTPCode := "123456"

	tests := []TableDrivenTestCase{
		{
			Name: "Delete existing user successfully",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()
				hasher := utils.NewPasswordHasher()

				// Create and verify a test user
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "deleteuser@example.com",
					Password: "password123",
				})
				if err != nil {
					return err
				}

				otpHashCode, _ := hasher.Hash(testOTPCode)
				if err := f.TestDB.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", signupResp.OTPHash).
					Update("hashed_code", otpHashCode).Error; err != nil {
					return err
				}

				_, err = authService.VerifyOTP(f.Ctx, service.VerifyOTPRequest{
					OTPHash: signupResp.OTPHash,
					Code:    testOTPCode,
				})
				return err
			},
			Test: func(f *TestFixture) error {
				// Get a valid session
				var session domain.Session
				require.NoError(f.T, f.TestDB.DB.Where("deleted_at IS NULL").First(&session).Error)

				// Get the user
				var user domain.User
				require.NoError(f.T, f.TestDB.DB.Where("id = ?", session.UserID).First(&user).Error)

				// Add token to context
				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				resp, err := f.GRPCClient.DeleteUser(ctxWithToken, &pb.DeleteUserRequest{UserId: int64(user.ID)})

				require.NoError(f.T, err)
				require.NotEmpty(f.T, resp.Message, "expected message in response")

				// Verify user is actually deleted
				_, verifyErr := f.GRPCClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: int64(user.ID)})
				require.Error(f.T, verifyErr, "expected error when getting deleted user")

				return nil
			},
			ExpectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			fixture := NewTestFixture(t)
			fixture.Setup()

			if err := tt.Setup(fixture); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			err := tt.Test(fixture)
			if (err != nil) != tt.ExpectError {
				t.Errorf("test failed: got error %v, want error %v", err, tt.ExpectError)
			}

			if tt.Verify != nil {
				if err := tt.Verify(fixture); err != nil {
					t.Errorf("verification failed: %v", err)
				}
			}
		})
	}
}
