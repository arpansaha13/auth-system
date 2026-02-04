package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/metadata"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/pb"
)

// UserTestSuite is a test suite for user endpoints
type UserTestSuite struct {
	BaseTestSuite
}

// SetupTest prepares each test
func (s *UserTestSuite) SetupTest() {
	s.CleanupTablesForSuite()
}

// TestGetUserEndpoint tests the GetUser gRPC endpoint
func (s *UserTestSuite) TestGetUser() {
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
				s.Require().NoError(f.TestDB.DB.Where("deleted_at IS NULL").First(&session).Error)

				// Get the user
				var user domain.User
				s.Require().NoError(f.TestDB.DB.Where("id = ?", session.UserID).First(&user).Error)

				// Add token to context
				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				resp, err := f.GRPCClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: int64(user.ID)})

				s.Require().NoError(err)
				s.Require().NotNil(resp.User, "expected user in response")
				s.Require().Equal("getuser@example.com", resp.User.Email, "email mismatch")
				s.Require().True(resp.User.Verified, "expected user to be verified")
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
				s.Require().Error(err, "expected error for non-existent user")
				// If we got an error as expected, that's success
				s.Require().Nil(resp)
				return nil
			},
			ExpectError: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.Name, func() {
			fixture := NewTestFixtureWithSuite(s)
			fixture.Setup()

			if err := tt.Setup(fixture); err != nil {
				s.T().Fatalf("setup failed: %v", err)
			}

			err := tt.Test(fixture)
			if (err != nil) != tt.ExpectError {
				s.T().Errorf("test failed: got error %v, want error %v", err, tt.ExpectError)
			}

			if tt.Verify != nil {
				if err := tt.Verify(fixture); err != nil {
					s.T().Errorf("verification failed: %v", err)
				}
			}
		})
	}
}

// TestGetUserByEmailEndpoint tests the GetUserByEmail gRPC endpoint
func (s *UserTestSuite) TestGetUserByEmail() {
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

				s.Require().NoError(err)
				s.Require().NotNil(resp.User, "expected user in response")
				s.Require().Equal("getuserbyemail@example.com", resp.User.Email, "email mismatch")
				s.Require().True(resp.User.Verified, "expected user to be verified")
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
				s.Require().Error(err, "expected error for non-existent email")
				// If we got an error as expected, that's success
				s.Require().Nil(resp)
				return nil
			},
			ExpectError: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.Name, func() {
			fixture := NewTestFixtureWithSuite(s)
			fixture.Setup()

			if err := tt.Setup(fixture); err != nil {
				s.T().Fatalf("setup failed: %v", err)
			}

			err := tt.Test(fixture)
			if (err != nil) != tt.ExpectError {
				s.T().Errorf("test failed: got error %v, want error %v", err, tt.ExpectError)
			}

			if tt.Verify != nil {
				if err := tt.Verify(fixture); err != nil {
					s.T().Errorf("verification failed: %v", err)
				}
			}
		})
	}
}

// TestDeleteUserEndpoint tests the DeleteUser gRPC endpoint
func (s *UserTestSuite) TestDeleteUser() {
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
				s.Require().NoError(f.TestDB.DB.Where("deleted_at IS NULL").First(&session).Error)

				// Get the user
				var user domain.User
				s.Require().NoError(f.TestDB.DB.Where("id = ?", session.UserID).First(&user).Error)

				// Add token to context
				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				resp, err := f.GRPCClient.DeleteUser(ctxWithToken, &pb.DeleteUserRequest{UserId: int64(user.ID)})

				s.Require().NoError(err)
				s.Require().NotEmpty(resp.Message, "expected message in response")

				// Verify user is actually deleted
				_, verifyErr := f.GRPCClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: int64(user.ID)})
				s.Require().Error(verifyErr, "expected error when getting deleted user")

				return nil
			},
			ExpectError: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.Name, func() {
			fixture := NewTestFixtureWithSuite(s)
			fixture.Setup()

			if err := tt.Setup(fixture); err != nil {
				s.T().Fatalf("setup failed: %v", err)
			}

			err := tt.Test(fixture)
			if (err != nil) != tt.ExpectError {
				s.T().Errorf("test failed: got error %v, want error %v", err, tt.ExpectError)
			}

			if tt.Verify != nil {
				if err := tt.Verify(fixture); err != nil {
					s.T().Errorf("verification failed: %v", err)
				}
			}
		})
	}
}

// TestUserService runs the user management test suite
func TestUserService(t *testing.T) {
	suite.Run(t, new(UserTestSuite))
}
