package tests

import (
	"testing"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/pb"
	"google.golang.org/grpc/metadata"
)

// TestSignup tests the Signup gRPC endpoint with valid inputs
func TestSignup(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()

	t.Run("Successful signup", func(t *testing.T) {
		resp, err := client.Signup(ctx, &pb.SignupRequest{
			Email:    "signup@example.com",
			Password: "securePassword123",
		})

		if err != nil {
			t.Fatalf("Signup failed: %v", err)
		}
		if resp.Message == "" {
			t.Fatal("Expected message in response")
		}
		if resp.OtpHash == "" {
			t.Fatal("Expected OTP hash in response")
		}
	})
}

// TestVerifyOTP tests the VerifyOTP gRPC endpoint with valid inputs
func TestVerifyOTP(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	// First, signup to get OTP hash
	signupResp, err := authService.Signup(ctx, service.SignupRequest{
		Email:    "verify@example.com",
		Password: "securePassword123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	otpHash := signupResp.OTPHash

	// Update OTP with test code
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode)

	t.Run("Successful OTP verification", func(t *testing.T) {
		verifyResp, err := client.VerifyOTP(ctx, &pb.VerifyOTPRequest{
			OtpHash: otpHash,
			Code:    testOTP,
		})

		if err != nil {
			t.Fatalf("OTP verification failed: %v", err)
		}
		if verifyResp.Username == "" {
			t.Fatal("Expected username in response")
		}
		if verifyResp.SessionToken == "" {
			t.Fatal("Expected session token in response")
		}
	})
}

// TestLogin tests the Login gRPC endpoint with valid inputs
func TestLogin(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	// Signup and verify user
	signupResp, _ := authService.Signup(ctx, service.SignupRequest{
		Email:    "login@example.com",
		Password: "securePassword123",
	})

	otpHash := signupResp.OTPHash
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode)

	authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})

	t.Run("Successful login", func(t *testing.T) {
		loginResp, err := client.Login(ctx, &pb.LoginRequest{
			Email:    "login@example.com",
			Password: "securePassword123",
		})

		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if loginResp.SessionToken == "" {
			t.Fatal("Expected session token in response")
		}
		if loginResp.ExpiresAt == nil {
			t.Fatal("Expected expires_at in response")
		}
	})
}

// TestForgotPassword tests the ForgotPassword gRPC endpoint with valid inputs
func TestForgotPassword(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	// Create and verify user first
	signupResp, _ := authService.Signup(ctx, service.SignupRequest{
		Email:    "forgot@example.com",
		Password: "securePassword123",
	})

	otpHash := signupResp.OTPHash
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode)

	authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})

	t.Run("Successful forgot password request", func(t *testing.T) {
		forgotResp, err := client.ForgotPassword(ctx, &pb.ForgotPasswordRequest{
			Email: "forgot@example.com",
		})

		if err != nil {
			t.Fatalf("ForgotPassword failed: %v", err)
		}
		if forgotResp.Message == "" {
			t.Fatal("Expected message in response")
		}
		if forgotResp.OtpHash == "" {
			t.Fatal("Expected OTP hash in response")
		}
	})
}

// TestResetPassword tests the ResetPassword gRPC endpoint with valid inputs
func TestResetPassword(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	// Create, verify user, and initiate forgot password
	signupResp, _ := authService.Signup(ctx, service.SignupRequest{
		Email:    "reset@example.com",
		Password: "oldPassword123",
	})

	otpHash := signupResp.OTPHash
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode)

	authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})

	// Now forgot password
	forgotResp, _ := authService.ForgotPassword(ctx, service.ForgotPasswordRequest{
		Email: "reset@example.com",
	})

	resetOTPHash := forgotResp.OTPHash
	resetOTP := "654321"
	resetHashCode, _ := hasher.Hash(resetOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", resetOTPHash).
		Update("hashed_code", resetHashCode)

	t.Run("Successful password reset", func(t *testing.T) {
		resetResp, err := client.ResetPassword(ctx, &pb.ResetPasswordRequest{
			OtpHash:  resetOTPHash,
			Code:     resetOTP,
			Password: "newPassword123",
		})

		if err != nil {
			t.Fatalf("ResetPassword failed: %v", err)
		}
		if resetResp.Message == "" {
			t.Fatal("Expected message in response")
		}
	})
}

// TestValidateSession tests the ValidateSession gRPC endpoint with valid inputs
func TestValidateSession(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	// Create, verify user and login
	signupResp, _ := authService.Signup(ctx, service.SignupRequest{
		Email:    "validate@example.com",
		Password: "securePassword123",
	})

	otpHash := signupResp.OTPHash
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode)

	verifyResp, _ := authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})

	sessionToken := verifyResp.SessionToken

	t.Run("Valid session token", func(t *testing.T) {
		// Create context with token metadata
		md := metadata.Pairs("authorization", "Bearer "+sessionToken)
		ctxWithToken := metadata.NewOutgoingContext(ctx, md)

		validateResp, err := client.ValidateSession(ctxWithToken, &pb.ValidateSessionRequest{})

		if err != nil {
			t.Fatalf("ValidateSession failed: %v", err)
		}
		if !validateResp.Valid {
			t.Fatal("Expected valid session")
		}
		if validateResp.UserId == 0 {
			t.Fatal("Expected non-zero user ID")
		}
	})
}

// TestRefreshSession tests the RefreshSession gRPC endpoint with valid inputs
func TestRefreshSession(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	// Create, verify user and login
	signupResp, _ := authService.Signup(ctx, service.SignupRequest{
		Email:    "refresh@example.com",
		Password: "securePassword123",
	})

	otpHash := signupResp.OTPHash
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode)

	verifyResp, _ := authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})

	sessionToken := verifyResp.SessionToken

	t.Run("Successful session refresh", func(t *testing.T) {
		// Create context with token metadata
		md := metadata.Pairs("authorization", "Bearer "+sessionToken)
		ctxWithToken := metadata.NewOutgoingContext(ctx, md)

		refreshResp, err := client.RefreshSession(ctxWithToken, &pb.RefreshSessionRequest{})

		if err != nil {
			t.Fatalf("RefreshSession failed: %v", err)
		}
		if refreshResp.NewSessionToken == "" {
			t.Fatal("Expected new session token in response")
		}
	})
}
