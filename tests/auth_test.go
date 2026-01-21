package tests

import (
	"testing"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
)

// TestSignup tests the Signup endpoint
func TestSignup(t *testing.T) {
	type SetupReturn struct {
		Email string
	}

	testCases := []TestCase[*service.SignupRequest, *service.SignupResponse, *SetupReturn]{
		{
			Name: "Successful signup",
			Setup: func(t *testing.T) *SetupReturn {
				return &SetupReturn{
					Email: "newuser@example.com",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.SignupRequest {
				return &service.SignupRequest{
					Email:    setupData.Email,
					Password: "securePassword123",
				}
			},
			Validate: func(t *testing.T, resp *service.SignupResponse, setupData *SetupReturn) {
				if resp.Message == "" {
					t.Fatal("Expected message in response")
				}
				if resp.OTPHash == "" {
					t.Fatal("Expected OTP hash in response")
				}
			},
		},
		{
			Name: "Duplicate email",
			Setup: func(t *testing.T) *SetupReturn {
				// Create existing user
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()
				authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    "duplicate@example.com",
					Password: "securePassword123",
				})
				return &SetupReturn{
					Email: "duplicate@example.com",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.SignupRequest {
				return &service.SignupRequest{
					Email:    setupData.Email,
					Password: "securePassword123",
				}
			},
			ExpectError: true,
			ErrorType:   "conflict",
		},
	}

	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setupData := tc.Setup(t)
			resp, err := authService.Signup(testdb.Ctx, *tc.GetRequest(setupData))

			if tc.ExpectError {
				if err == nil {
					t.Fatal("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("Signup failed: %v", err)
			}

			if tc.Validate != nil {
				tc.Validate(t, resp, setupData)
			}
		})
	}
}

// TestVerifyOTP tests the VerifyOTP endpoint
func TestVerifyOTP(t *testing.T) {
	type SetupReturn struct {
		OTPHash string
		UserID  int64
		Email   string
	}

	testCases := []TestCase[*service.VerifyOTPRequest, *service.VerifyOTPResponse, *SetupReturn]{
		{
			Name: "Successful OTP verification",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()
				otpRepo := repository.NewOTPRepository(testdb.DB)

				signupResp, _ := authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    "verify-test@example.com",
					Password: "securePassword123",
				})

				otpHash := signupResp.OTPHash
				testOTP := "123456"
				hasher := utils.NewPasswordHasher()
				hashedOTP, _ := hasher.Hash(testOTP)

				testdb.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", otpHash).
					Update("hashed_code", hashedOTP)

				otp, _ := otpRepo.GetByOTPHash(testdb.Ctx, otpHash, domain.OTPPurposeSignupVerification)

				return &SetupReturn{
					OTPHash: otpHash,
					UserID:  otp.UserID,
					Email:   "verify-test@example.com",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.VerifyOTPRequest {
				return &service.VerifyOTPRequest{
					OTPHash: setupData.OTPHash,
					Code:    "123456",
				}
			},
			Validate: func(t *testing.T, resp *service.VerifyOTPResponse, setupData *SetupReturn) {
				if resp.Username == "" {
					t.Fatal("Expected username in response")
				}
				if resp.SessionToken == "" {
					t.Fatal("Expected session token in response")
				}
				if resp.OTPHash == "" {
					t.Fatal("Expected OTP hash in response")
				}
			},
		},
		{
			Name: "Invalid OTP code",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()

				signupResp, _ := authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    "invalid-otp@example.com",
					Password: "securePassword123",
				})

				otpHash := signupResp.OTPHash
				testOTP := "123456"
				hasher := utils.NewPasswordHasher()
				hashedOTP, _ := hasher.Hash(testOTP)

				testdb.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", otpHash).
					Update("hashed_code", hashedOTP)

				return &SetupReturn{
					OTPHash: otpHash,
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.VerifyOTPRequest {
				return &service.VerifyOTPRequest{
					OTPHash: setupData.OTPHash,
					Code:    "654321", // Wrong code
				}
			},
			ExpectError: true,
			ErrorType:   "unauthorized",
		},
	}

	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setupData := tc.Setup(t)
			resp, err := authService.VerifyOTP(testdb.Ctx, *tc.GetRequest(setupData))

			if tc.ExpectError {
				if err == nil {
					t.Fatal("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyOTP failed: %v", err)
			}

			if tc.Validate != nil {
				tc.Validate(t, resp, setupData)
			}
		})
	}
}

// TestLogin tests the Login endpoint
func TestLogin(t *testing.T) {
	type SetupReturn struct {
		Email    string
		Password string
		Verified bool
	}

	testCases := []TestCase[*service.LoginRequest, *service.LoginResponse, *SetupReturn]{
		{
			Name: "Successful login after verification",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()

				email := "login-test@example.com"
				password := "securePassword123"

				signupResp, _ := authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    email,
					Password: password,
				})

				otpHash := signupResp.OTPHash
				testOTP := "123456"
				hasher := utils.NewPasswordHasher()
				hashedOTP, _ := hasher.Hash(testOTP)

				testdb.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", otpHash).
					Update("hashed_code", hashedOTP)

				authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
					OTPHash: otpHash,
					Code:    testOTP,
				})

				return &SetupReturn{
					Email:    email,
					Password: password,
					Verified: true,
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.LoginRequest {
				return &service.LoginRequest{
					Email:    setupData.Email,
					Password: setupData.Password,
				}
			},
			Validate: func(t *testing.T, resp *service.LoginResponse, setupData *SetupReturn) {
				if resp.SessionToken == "" {
					t.Fatal("Expected session token in response")
				}
			},
		},
		{
			Name: "Login before email verification",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()

				email := "unverified@example.com"
				password := "securePassword123"

				authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    email,
					Password: password,
				})

				return &SetupReturn{
					Email:    email,
					Password: password,
					Verified: false,
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.LoginRequest {
				return &service.LoginRequest{
					Email:    setupData.Email,
					Password: setupData.Password,
				}
			},
			ExpectError: true,
			ErrorType:   "unauthorized",
		},
		{
			Name: "Wrong password",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()

				email := "wrong-pass@example.com"
				password := "securePassword123"

				signupResp, _ := authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    email,
					Password: password,
				})

				otpHash := signupResp.OTPHash
				testOTP := "123456"
				hasher := utils.NewPasswordHasher()
				hashedOTP, _ := hasher.Hash(testOTP)

				testdb.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", otpHash).
					Update("hashed_code", hashedOTP)

				authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
					OTPHash: otpHash,
					Code:    testOTP,
				})

				return &SetupReturn{
					Email:    email,
					Password: "wrongPassword",
					Verified: true,
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.LoginRequest {
				return &service.LoginRequest{
					Email:    setupData.Email,
					Password: setupData.Password,
				}
			},
			ExpectError: true,
			ErrorType:   "unauthorized",
		},
	}

	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setupData := tc.Setup(t)
			resp, err := authService.Login(testdb.Ctx, *tc.GetRequest(setupData))

			if tc.ExpectError {
				if err == nil {
					t.Fatal("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("Login failed: %v", err)
			}

			if tc.Validate != nil {
				tc.Validate(t, resp, setupData)
			}
		})
	}
}

// TestForgotPassword tests the ForgotPassword endpoint
func TestForgotPassword(t *testing.T) {
	type SetupReturn struct {
		Email string
	}

	testCases := []TestCase[*service.ForgotPasswordRequest, *service.ForgotPasswordResponse, *SetupReturn]{
		{
			Name: "Successful forgot password request",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()

				// Create and verify a user first
				authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    "forgot@example.com",
					Password: "securePassword123",
				})

				return &SetupReturn{
					Email: "forgot@example.com",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.ForgotPasswordRequest {
				return &service.ForgotPasswordRequest{
					Email: setupData.Email,
				}
			},
			Validate: func(t *testing.T, resp *service.ForgotPasswordResponse, setupData *SetupReturn) {
				if resp.Message == "" {
					t.Fatal("Expected message in response")
				}
				if resp.OTPHash == "" {
					t.Fatal("Expected OTP hash in response")
				}
			},
		},
		{
			Name: "Forgot password with non-existent email",
			Setup: func(t *testing.T) *SetupReturn {
				return &SetupReturn{
					Email: "nonexistent@example.com",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.ForgotPasswordRequest {
				return &service.ForgotPasswordRequest{
					Email: setupData.Email,
				}
			},
			Validate: func(t *testing.T, resp *service.ForgotPasswordResponse, setupData *SetupReturn) {
				// Should return generic message to avoid email enumeration
				if resp.Message == "" {
					t.Fatal("Expected message in response")
				}
			},
		},
	}

	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setupData := tc.Setup(t)
			resp, err := authService.ForgotPassword(testdb.Ctx, *tc.GetRequest(setupData))

			if tc.ExpectError {
				if err == nil {
					t.Fatal("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("ForgotPassword failed: %v", err)
			}

			if tc.Validate != nil {
				tc.Validate(t, resp, setupData)
			}
		})
	}
}

// TestResetPassword tests the ResetPassword endpoint
func TestResetPassword(t *testing.T) {
	type SetupReturn struct {
		OTPHash string
		UserID  int64
		Email   string
	}

	testCases := []TestCase[*service.ResetPasswordRequest, *service.ResetPasswordResponse, *SetupReturn]{
		{
			Name: "Successful password reset",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()
				otpRepo := repository.NewOTPRepository(testdb.DB)

				// Create a user
				authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    "reset@example.com",
					Password: "oldPassword123",
				})

				// Initiate forgot password
				forgotResp, _ := authService.ForgotPassword(testdb.Ctx, service.ForgotPasswordRequest{
					Email: "reset@example.com",
				})

				otpHash := forgotResp.OTPHash
				testOTP := "123456"
				hasher := utils.NewPasswordHasher()
				hashedOTP, _ := hasher.Hash(testOTP)

				// Update OTP with test code
				testdb.DB.Model(&domain.OTP{}).
					Where("otp_hash = ? AND purpose = ?", otpHash, domain.OTPPurposeResetPassword).
					Update("hashed_code", hashedOTP)

				otp, _ := otpRepo.GetByOTPHash(testdb.Ctx, otpHash, domain.OTPPurposeResetPassword)
				return &SetupReturn{
					OTPHash: otpHash,
					UserID:  otp.UserID,
					Email:   "reset@example.com",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.ResetPasswordRequest {
				return &service.ResetPasswordRequest{
					OTPHash:  setupData.OTPHash,
					Code:     "123456",
					Password: "newPassword123",
				}
			},
			Validate: func(t *testing.T, resp *service.ResetPasswordResponse, setupData *SetupReturn) {
				if resp.Message == "" {
					t.Fatal("Expected confirmation message")
				}
			},
		},
		{
			Name: "Reset password with invalid OTP code",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()
				otpRepo := repository.NewOTPRepository(testdb.DB)

				// Create a user
				authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    "reset-invalid@example.com",
					Password: "oldPassword123",
				})

				// Initiate forgot password
				forgotResp, _ := authService.ForgotPassword(testdb.Ctx, service.ForgotPasswordRequest{
					Email: "reset-invalid@example.com",
				})

				otpHash := forgotResp.OTPHash
				testOTP := "123456"
				hasher := utils.NewPasswordHasher()
				hashedOTP, _ := hasher.Hash(testOTP)

				testdb.DB.Model(&domain.OTP{}).
					Where("otp_hash = ? AND purpose = ?", otpHash, domain.OTPPurposeResetPassword).
					Update("hashed_code", hashedOTP)

				otp, _ := otpRepo.GetByOTPHash(testdb.Ctx, otpHash, domain.OTPPurposeResetPassword)
				return &SetupReturn{
					OTPHash: otpHash,
					UserID:  otp.UserID,
					Email:   "reset-invalid@example.com",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.ResetPasswordRequest {
				return &service.ResetPasswordRequest{
					OTPHash:  setupData.OTPHash,
					Code:     "654321", // Wrong code
					Password: "newPassword123",
				}
			},
			ExpectError: true,
			ErrorType:   "unauthorized",
		},
	}

	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setupData := tc.Setup(t)
			resp, err := authService.ResetPassword(testdb.Ctx, *tc.GetRequest(setupData))

			if tc.ExpectError {
				if err == nil {
					t.Fatal("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("ResetPassword failed: %v", err)
			}

			if tc.Validate != nil {
				tc.Validate(t, resp, setupData)
			}
		})
	}
}

// TestValidateSession tests the ValidateSession endpoint
func TestValidateSession(t *testing.T) {
	type SetupReturn struct {
		SessionToken string
		UserID       int64
	}

	testCases := []TestCase[*service.ValidateSessionRequest, *service.ValidateSessionResponse, *SetupReturn]{
		{
			Name: "Valid session token",
			Setup: func(t *testing.T) *SetupReturn {
				testdb := CreateTestDB(t)
				authService := testdb.CreateAuthService()

				signupResp, _ := authService.Signup(testdb.Ctx, service.SignupRequest{
					Email:    "validate@example.com",
					Password: "securePassword123",
				})

				otpHash := signupResp.OTPHash
				testOTP := "123456"
				hasher := utils.NewPasswordHasher()
				hashedOTP, _ := hasher.Hash(testOTP)

				testdb.DB.Model(&domain.OTP{}).
					Where("otp_hash = ?", otpHash).
					Update("hashed_code", hashedOTP)

				verifyResp, _ := authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
					OTPHash: otpHash,
					Code:    testOTP,
				})

				return &SetupReturn{
					SessionToken: verifyResp.SessionToken,
					UserID:       0, // Will be populated by service
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.ValidateSessionRequest {
				return &service.ValidateSessionRequest{
					Token: setupData.SessionToken,
				}
			},
			Validate: func(t *testing.T, resp *service.ValidateSessionResponse, setupData *SetupReturn) {
				if !resp.Valid {
					t.Fatal("Expected valid session")
				}
				if resp.UserID == 0 {
					t.Fatal("Expected user ID in response")
				}
			},
		},
		{
			Name: "Invalid session token",
			Setup: func(t *testing.T) *SetupReturn {
				return &SetupReturn{
					SessionToken: "invalid_token",
				}
			},
			GetRequest: func(setupData *SetupReturn) *service.ValidateSessionRequest {
				return &service.ValidateSessionRequest{
					Token: setupData.SessionToken,
				}
			},
			Validate: func(t *testing.T, resp *service.ValidateSessionResponse, setupData *SetupReturn) {
				if resp.Valid {
					t.Fatal("Expected invalid session")
				}
			},
		},
	}

	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setupData := tc.Setup(t)
			resp, err := authService.ValidateSession(testdb.Ctx, *tc.GetRequest(setupData))

			if err != nil {
				t.Fatalf("ValidateSession failed: %v", err)
			}

			if tc.Validate != nil {
				tc.Validate(t, resp, setupData)
			}
		})
	}
}
