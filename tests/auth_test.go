package tests

import (
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/pb"
)

// TestSignupEndpoint tests the Signup gRPC endpoint
func TestSignup(t *testing.T) {
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

				if err != nil {
					return err
				}
				if resp.Message == "" {
					return &domain.ValidationError{Message: "expected message in response"}
				}
				if resp.OtpHash == "" {
					return &domain.ValidationError{Message: "expected OTP hash in response"}
				}
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
				if err == nil {
					return &domain.ValidationError{Message: "expected error for duplicate email"}
				}
				// If we got an error as expected, that's success
				if resp == nil {
					return nil
				}
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

// TestVerifyOTPEndpoint tests the VerifyOTP gRPC endpoint
func TestVerifyOTP(t *testing.T) {
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
				if err := f.TestDB.DB.Where("user_id IN (SELECT id FROM users WHERE email = ?)", testEmail).
					First(&otp).Error; err != nil {
					return err
				}

				verifyResp, err := f.GRPCClient.VerifyOTP(f.Ctx, &pb.VerifyOTPRequest{
					OtpHash: otp.OTPHash,
					Code:    testOTPCode,
				})

				if err != nil {
					return err
				}
				if verifyResp.Username == "" {
					return &domain.ValidationError{Message: "expected username in response"}
				}
				if verifyResp.SessionToken == "" {
					return &domain.ValidationError{Message: "expected session token in response"}
				}
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
				if err := f.TestDB.DB.Where("user_id IN (SELECT id FROM users WHERE email = ?)", "verify-wrong@example.com").
					First(&otp).Error; err != nil {
					return err
				}

				verifyResp, err := f.GRPCClient.VerifyOTP(f.Ctx, &pb.VerifyOTPRequest{
					OtpHash: otp.OTPHash,
					Code:    "wrong-code",
				})

				// We expect an error for incorrect code
				if err == nil {
					return &domain.ValidationError{Message: "expected error for incorrect OTP code"}
				}
				// If we got an error as expected, that's success
				if verifyResp == nil {
					return nil
				}
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

// TestLoginEndpoint tests the Login gRPC endpoint
func TestLogin(t *testing.T) {
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

				if err != nil {
					return err
				}
				if loginResp.SessionToken == "" {
					return &domain.ValidationError{Message: "expected session token in response"}
				}
				if loginResp.ExpiresAt == nil {
					return &domain.ValidationError{Message: "expected expiration time in response"}
				}
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
				if err == nil {
					return &domain.ValidationError{Message: "expected error for unverified user"}
				}
				// If we got an error as expected, that's success for this test
				if loginResp == nil {
					return nil
				}
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

// TestForgotPasswordEndpoint tests the ForgotPassword gRPC endpoint
func TestForgotPassword(t *testing.T) {
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

				if err != nil {
					return err
				}
				if forgotResp.Message == "" {
					return &domain.ValidationError{Message: "expected message in response"}
				}
				if forgotResp.OtpHash == "" {
					return &domain.ValidationError{Message: "expected OTP hash in response"}
				}
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

// TestResetPasswordEndpoint tests the ResetPassword gRPC endpoint
func TestResetPassword(t *testing.T) {
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
				if err := f.TestDB.DB.Where("user_id IN (SELECT id FROM users WHERE email = ?)", "reset@example.com").
					Order("created_at DESC").
					First(&otp).Error; err != nil {
					return err
				}

				resetResp, err := f.GRPCClient.ResetPassword(f.Ctx, &pb.ResetPasswordRequest{
					OtpHash:  otp.OTPHash,
					Code:     resetOTPCode,
					Password: "newPassword123",
				})

				if err != nil {
					return err
				}
				if resetResp.Message == "" {
					return &domain.ValidationError{Message: "expected message in response"}
				}
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

// TestValidateSessionEndpoint tests the ValidateSession gRPC endpoint
func TestValidateSession(t *testing.T) {
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
				if err != nil {
					return err
				}

				// Create context with token metadata
				md := metadata.Pairs("authorization", "Bearer "+loginResp.SessionToken)
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				validateResp, err := f.GRPCClient.ValidateSession(ctxWithToken, &pb.ValidateSessionRequest{})

				if err != nil {
					return err
				}
				if !validateResp.Valid {
					return &domain.ValidationError{Message: "expected valid session"}
				}
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

// TestRefreshSessionEndpoint tests the RefreshSession gRPC endpoint
func TestRefreshSession(t *testing.T) {
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
				if err != nil {
					return err
				}

				// Create context with token metadata
				md := metadata.Pairs("authorization", "Bearer "+loginResp.SessionToken)
				ctxWithToken := metadata.NewOutgoingContext(f.Ctx, md)

				refreshResp, err := f.GRPCClient.RefreshSession(ctxWithToken, &pb.RefreshSessionRequest{})

				if err != nil {
					return err
				}
				if refreshResp.NewSessionToken == "" {
					return &domain.ValidationError{Message: "expected new token in response"}
				}
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
