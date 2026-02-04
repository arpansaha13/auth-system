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

// AuthTestSuite is a test suite for auth endpoints
type AuthTestSuite struct {
	BaseTestSuite
}

// SetupTest prepares each test
func (s *AuthTestSuite) SetupTest() {
	s.CleanupTablesForSuite()
}

// TestSignupEndpoint tests the Signup gRPC endpoint
func (s *AuthTestSuite) TestSignup() {
	tests := []TableDrivenTestCase{
		{
			Name: "Signup with valid email and password",
			Setup: func(f *TestFixture) error {
				return nil
			},
			Test: func(f *TestFixture) error {
				resp, err := f.GRPCClient.Signup(f.Ctx, &pb.SignupRequest{
					Email:    "signup@example.com",
					Password: "securePassword123",
				})

				s.Require().NoError(err)
				s.Require().NotEmpty(resp.Message, "expected message in response")
				s.Require().NotEmpty(resp.OtpHash, "expected OTP hash in response")
				return nil
			},
			ExpectError: false,
		},
		{
			Name: "Signup with duplicate email returns error",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()
				_, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "duplicate@example.com",
					Password: "password123",
				})
				return err
			},
			Test: func(f *TestFixture) error {
				resp, err := f.GRPCClient.Signup(f.Ctx, &pb.SignupRequest{
					Email:    "duplicate@example.com",
					Password: "securePassword123",
				})

				// We expect an error for duplicate email
				s.Require().Error(err, "expected error for duplicate email")
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

// TestVerifyOTPEndpoint tests the VerifyOTP gRPC endpoint
func (s *AuthTestSuite) TestVerifyOTP() {
	testOTPCode := "123456"
	testEmail := "verify@example.com"

	tests := []TableDrivenTestCase{
		{
			Name: "Verify OTP with correct code",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()

				// Signup to get OTP hash
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    testEmail,
					Password: "securePassword123",
				})
				if err != nil {
					return err
				}

				// Update OTP with test code
				hasher := utils.NewPasswordHasher()
				otpHashCode, _ := hasher.Hash(testOTPCode)
				return f.TestDB.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", signupResp.OTPHash).
					Update("hashed_code", otpHashCode).Error
			},
			Test: func(f *TestFixture) error {
				// Get the OTP by looking for one with hashed code set
				var otp domain.OTP
				s.Require().NoError(f.TestDB.DB.Where("user_id IN (SELECT id FROM users WHERE email = ?)", testEmail).
					First(&otp).Error)

				verifyResp, err := f.GRPCClient.VerifyOTP(f.Ctx, &pb.VerifyOTPRequest{
					OtpHash: otp.OTPHash,
					Code:    testOTPCode,
				})

				s.Require().NoError(err)
				s.Require().NotEmpty(verifyResp.Username, "expected username in response")
				s.Require().NotEmpty(verifyResp.SessionToken, "expected session token in response")
				return nil
			},
			ExpectError: false,
		},
		{
			Name: "Verify OTP with incorrect code returns error",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()

				// Signup to get OTP hash
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "verify-wrong@example.com",
					Password: "securePassword123",
				})
				if err != nil {
					return err
				}

				hasher := utils.NewPasswordHasher()
				otpHashCode, _ := hasher.Hash(testOTPCode)
				return f.TestDB.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", signupResp.OTPHash).
					Update("hashed_code", otpHashCode).Error
			},
			Test: func(f *TestFixture) error {
				var otp domain.OTP
				s.Require().NoError(f.TestDB.DB.Where("user_id IN (SELECT id FROM users WHERE email = ?)", "verify-wrong@example.com").
					First(&otp).Error)

				verifyResp, err := f.GRPCClient.VerifyOTP(f.Ctx, &pb.VerifyOTPRequest{
					OtpHash: otp.OTPHash,
					Code:    "wrong-code",
				})

				// We expect an error for incorrect code
				s.Require().Error(err, "expected error for incorrect OTP code")
				// If we got an error as expected, that's success
				s.Require().Nil(verifyResp)
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

// TestLoginEndpoint tests the Login gRPC endpoint
func (s *AuthTestSuite) TestLogin() {
	testOTPCode := "123456"

	tests := []TableDrivenTestCase{
		{
			Name: "Login with verified email and password",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()

				// Signup and verify user
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "login@example.com",
					Password: "securePassword123",
				})
				if err != nil {
					return err
				}

				hasher := utils.NewPasswordHasher()
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
				loginResp, err := f.GRPCClient.Login(f.Ctx, &pb.LoginRequest{
					Email:    "login@example.com",
					Password: "securePassword123",
				})

				s.Require().NoError(err)
				s.Require().NotEmpty(loginResp.SessionToken, "expected session token in response")
				s.Require().NotNil(loginResp.ExpiresAt, "expected expiration time in response")
				return nil
			},
			ExpectError: false,
		},
		{
			Name: "Login with unverified user returns error",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()
				_, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "unverified@example.com",
					Password: "securePassword123",
				})
				return err
			},
			Test: func(f *TestFixture) error {
				loginResp, err := f.GRPCClient.Login(f.Ctx, &pb.LoginRequest{
					Email:    "unverified@example.com",
					Password: "securePassword123",
				})

				// We expect an error for unverified user
				s.Require().Error(err, "expected error for unverified user")
				// If we got an error as expected, that's success for this test
				s.Require().Nil(loginResp)
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

// TestForgotPasswordEndpoint tests the ForgotPassword gRPC endpoint
func (s *AuthTestSuite) TestForgotPassword() {
	testOTPCode := "123456"

	tests := []TableDrivenTestCase{
		{
			Name: "ForgotPassword with valid email",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()

				// Create and verify user first
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "forgot@example.com",
					Password: "securePassword123",
				})
				if err != nil {
					return err
				}

				hasher := utils.NewPasswordHasher()
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
				forgotResp, err := f.GRPCClient.ForgotPassword(f.Ctx, &pb.ForgotPasswordRequest{
					Email: "forgot@example.com",
				})

				s.Require().NoError(err)
				s.Require().NotEmpty(forgotResp.Message, "expected message in response")
				s.Require().NotEmpty(forgotResp.OtpHash, "expected OTP hash in response")
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

// TestResetPasswordEndpoint tests the ResetPassword gRPC endpoint
func (s *AuthTestSuite) TestResetPassword() {
	testOTPCode := "123456"
	resetOTPCode := "654321"

	tests := []TableDrivenTestCase{
		{
			Name: "ResetPassword with valid OTP and new password",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()
				hasher := utils.NewPasswordHasher()

				// Create, verify user, and initiate forgot password
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "reset@example.com",
					Password: "oldPassword123",
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
				if err != nil {
					return err
				}

				// Now forgot password
				forgotResp, err := authService.ForgotPassword(f.Ctx, service.ForgotPasswordRequest{
					Email: "reset@example.com",
				})
				if err != nil {
					return err
				}

				resetHashCode, _ := hasher.Hash(resetOTPCode)
				return f.TestDB.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", forgotResp.OTPHash).
					Update("hashed_code", resetHashCode).Error
			},
			Test: func(f *TestFixture) error {
				// Get the most recent OTP (reset password OTP)
				var otp domain.OTP
				s.Require().NoError(f.TestDB.DB.Where("user_id IN (SELECT id FROM users WHERE email = ?)", "reset@example.com").
					Order("created_at DESC").
					First(&otp).Error)

				resetResp, err := f.GRPCClient.ResetPassword(f.Ctx, &pb.ResetPasswordRequest{
					OtpHash:  otp.OTPHash,
					Code:     resetOTPCode,
					Password: "newPassword123",
				})

				s.Require().NoError(err)
				s.Require().NotEmpty(resetResp.Message, "expected message in response")
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

// TestValidateSessionEndpoint tests the ValidateSession gRPC endpoint
func (s *AuthTestSuite) TestValidateSession() {
	testOTPCode := "123456"

	tests := []TableDrivenTestCase{
		{
			Name: "ValidateSession with valid token",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()

				// Create, verify user and login
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "validate@example.com",
					Password: "securePassword123",
				})
				if err != nil {
					return err
				}

				hasher := utils.NewPasswordHasher()
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
				// Login to get a valid session
				loginResp, err := f.GRPCClient.Login(f.Ctx, &pb.LoginRequest{
					Email:    "validate@example.com",
					Password: "securePassword123",
				})
				s.Require().NoError(err)

				// Create context with token metadata
				md := metadata.Pairs("authorization", "Bearer "+loginResp.SessionToken)
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				validateResp, err := f.GRPCClient.ValidateSession(ctxWithToken, &pb.ValidateSessionRequest{})

				s.Require().NoError(err)
				s.Require().True(validateResp.Valid, "expected valid session")
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

// TestRefreshSessionEndpoint tests the RefreshSession gRPC endpoint
func (s *AuthTestSuite) TestRefreshSession() {
	testOTPCode := "123456"

	tests := []TableDrivenTestCase{
		{
			Name: "RefreshSession with valid token",
			Setup: func(f *TestFixture) error {
				authService := f.TestDB.CreateAuthService()

				// Create, verify user and login
				signupResp, err := authService.Signup(f.Ctx, service.SignupRequest{
					Email:    "refresh@example.com",
					Password: "securePassword123",
				})
				if err != nil {
					return err
				}

				hasher := utils.NewPasswordHasher()
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
				// Login to get a valid session
				loginResp, err := f.GRPCClient.Login(f.Ctx, &pb.LoginRequest{
					Email:    "refresh@example.com",
					Password: "securePassword123",
				})
				s.Require().NoError(err)

				// Create context with token metadata
				md := metadata.Pairs("authorization", "Bearer "+loginResp.SessionToken)
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				refreshResp, err := f.GRPCClient.RefreshSession(ctxWithToken, &pb.RefreshSessionRequest{})

				s.Require().NoError(err)
				s.Require().NotEmpty(refreshResp.NewSessionToken, "expected new token in response")
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

// TestAuthService runs the authentication test suite
func TestAuthService(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
