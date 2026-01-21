package tests

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/internal/worker"
)

// TestDB holds database resources for tests (deprecated, use shared global)
type TestDB struct {
	DB  *gorm.DB
	Ctx context.Context
}

// CreateTestDB creates a test database connection using shared global resources
func CreateTestDB(t *testing.T) *TestDB {
	// Clean tables before test
	CleanupTables(t)

	return &TestDB{
		DB:  GetTestDB(),
		Ctx: GetTestContext(),
	}
}

// CreateAuthService creates an auth service for testing
func (tdb *TestDB) CreateAuthService() *service.AuthService {
	userRepo := repository.NewUserRepository(tdb.DB)
	otpRepo := repository.NewOTPRepository(tdb.DB)
	sessionRepo := repository.NewSessionRepository(tdb.DB)
	hasher := utils.NewPasswordHasher()
	validator := utils.NewValidator()
	emailProvider := worker.NewMockEmailProvider()

	// Create email worker pool with 2 workers for testing
	emailPool := worker.NewEmailWorkerPool(2, 50, emailProvider)

	return service.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		hasher,
		validator,
		service.AuthServiceConfig{
			OTPExpiry:  10 * time.Minute,
			OTPLength:  6,
			SessionTTL: 30 * time.Minute,
			SecretKey:  "test-secret-key-at-least-32-characters-long-ok",
			EmailPool:  emailPool,
		},
	)
}

// TestSignupFlow tests the complete signup flow
func TestSignupFlow(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()

	// Test signup
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	if signupResp.OTPHash == "" {
		t.Fatal("Expected OTP hash in response")
	}

	if signupResp.Message == "" {
		t.Fatal("Expected message in response")
	}

	t.Logf("Signup successful: %s, OTP Hash: %s", signupResp.Message, signupResp.OTPHash)
}

// TestSignupDuplicate tests duplicate email prevention
func TestSignupDuplicate(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()

	// First signup
	_, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("First signup failed: %v", err)
	}

	// Duplicate signup
	_, err = authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "anotherPassword123",
	})

	if err == nil {
		t.Fatal("Expected error for duplicate email")
	}

	if !domain.IsConflict(err) {
		t.Fatalf("Expected ConflictError, got: %T", err)
	}

	t.Logf("Duplicate signup correctly prevented: %v", err)
}

// TestLoginBeforeVerification tests that login fails before email verification
func TestLoginBeforeVerification(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()

	// Signup
	_, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	// Try to login before verification
	_, err = authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err == nil {
		t.Fatal("Expected error when logging in before email verification")
	}

	if !domain.IsUnauthorized(err) {
		t.Fatalf("Expected UnauthorizedError, got: %T", err)
	}

	t.Logf("Login correctly blocked before verification: %v", err)
}

// TestCompleteAuthFlow tests the complete authentication flow
func TestCompleteAuthFlow(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()
	otpRepo := repository.NewOTPRepository(testdb.DB)

	// Step 1: Signup
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	otpHash := signupResp.OTPHash

	if otpHash == "" {
		t.Fatal("Expected OTP hash in signup response")
	}

	// Step 2: Get OTP from database (simulate email)
	_, err = otpRepo.GetByOTPHash(testdb.Ctx, otpHash, domain.OTPPurposeSignupVerification)
	if err != nil {
		t.Fatalf("Failed to get OTP: %v", err)
	}

	// For testing, we need to update the OTP code hash
	hasher := utils.NewPasswordHasher()
	testOTP := "123456"
	hash, _ := hasher.Hash(testOTP)
	if err := testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", hash).Error; err != nil {
		t.Fatalf("Failed to set hash: %v", err)
	}

	// Step 3: Verify OTP using OTP hash from signup response
	verifyResp, err := authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})

	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}

	if verifyResp.SessionToken == "" {
		t.Fatal("Expected session token in verification response")
	}

	if verifyResp.OTPHash == "" {
		t.Fatal("Expected OTP hash in verification response")
	}

	t.Logf("OTP verified, username: %s, OTP hash: %s", verifyResp.Username, verifyResp.OTPHash)

	// Step 4: Login
	loginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if loginResp.SessionToken == "" {
		t.Fatal("Expected session token in login response")
	}

	// Step 5: Validate session
	validateResp, err := authService.ValidateSession(testdb.Ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})

	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}

	if !validateResp.Valid {
		t.Fatal("Expected session to be valid")
	}

	t.Log("Complete auth flow successful")
}

// TestSessionRefresh tests session refresh
func TestSessionRefresh(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()

	// Complete signup, verify OTP, and login flow to get a valid session
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "refresh-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	otpHash := signupResp.OTPHash

	// Prepare and verify OTP
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	if err := testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode).Error; err != nil {
		t.Fatalf("Failed to set hash: %v", err)
	}

	_, err = authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})
	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}

	// Login to get a valid session token
	loginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "refresh-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	oldToken := loginResp.SessionToken

	// Test refresh with valid token
	refreshResp, err := authService.RefreshSession(testdb.Ctx, service.RefreshSessionRequest{
		Token: oldToken,
	})

	if err != nil {
		t.Fatalf("Session refresh failed: %v", err)
	}

	if refreshResp.NewSessionToken == "" {
		t.Fatal("Expected new session token")
	}

	if refreshResp.NewSessionToken == oldToken {
		t.Fatal("Expected different token after refresh")
	}

	t.Log("Session refresh successful")
}

// TestLogout tests the logout functionality
func TestLogout(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()

	// Step 1: Signup
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "logout-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	otpHash := signupResp.OTPHash

	// Step 2: Prepare and verify OTP
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	if err := testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode).Error; err != nil {
		t.Fatalf("Failed to set hash: %v", err)
	}

	// Step 3: Verify OTP
	_, err = authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})
	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}

	// Step 4: Login
	loginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "logout-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Step 5: Verify session is valid before logout
	validateResp, err := authService.ValidateSession(testdb.Ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})
	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}

	if !validateResp.Valid {
		t.Fatal("Expected session to be valid before logout")
	}

	// Step 6: Logout
	logoutResp, err := authService.Logout(testdb.Ctx, service.LogoutRequest{
		Token: loginResp.SessionToken,
	})
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	if logoutResp.Message != "logout successful" {
		t.Fatalf("Expected logout success message, got: %s", logoutResp.Message)
	}

	// Step 7: Verify session is invalid after logout
	validateAfterLogout, err := authService.ValidateSession(testdb.Ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})
	if err != nil {
		t.Fatalf("Session validation after logout failed: %v", err)
	}

	if validateAfterLogout.Valid {
		t.Fatal("Expected session to be invalid after logout")
	}

	t.Log("Logout successful and session invalidated")
}

// TestForgotAndResetPasswordFlow tests the complete forgot and reset password flow
func TestForgotAndResetPasswordFlow(t *testing.T) {
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()
	otpRepo := repository.NewOTPRepository(testdb.DB)

	// Step 1: Signup and verify user
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "reset-flow@example.com",
		Password: "oldPassword123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	otpHash := signupResp.OTPHash

	// Prepare OTP for verification
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode)

	// Verify user
	_, err = authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})
	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}

	// Step 2: Initiate forgot password
	forgotResp, err := authService.ForgotPassword(testdb.Ctx, service.ForgotPasswordRequest{
		Email: "reset-flow@example.com",
	})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}

	forgotOTPHash := forgotResp.OTPHash
	if forgotOTPHash == "" {
		t.Fatal("Expected OTP hash from forgot password")
	}

	// Step 3: Get the OTP and prepare for reset
	forgotOTP := "654321" // Different OTP
	forgotHashCode, _ := hasher.Hash(forgotOTP)
	testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ? AND purpose = ?", forgotOTPHash, 2).
		Update("hashed_code", forgotHashCode)

	// Step 4: Reset password
	resetResp, err := authService.ResetPassword(testdb.Ctx, service.ResetPasswordRequest{
		OTPHash:  forgotOTPHash,
		Code:     forgotOTP,
		Password: "newPassword123",
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	if resetResp.Message != "password reset successfully" {
		t.Fatalf("Expected reset success message, got: %s", resetResp.Message)
	}

	// Step 5: Verify old password no longer works
	_, err = authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "reset-flow@example.com",
		Password: "oldPassword123",
	})
	if err == nil {
		t.Fatal("Expected login to fail with old password")
	}

	// Step 6: Verify new password works
	newLoginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "reset-flow@example.com",
		Password: "newPassword123",
	})
	if err != nil {
		t.Fatalf("Login with new password failed: %v", err)
	}

	if newLoginResp.SessionToken == "" {
		t.Fatal("Expected session token from new login")
	}

	// Step 7: Verify OTP is soft-deleted after reset
	_, err = otpRepo.GetByOTPHash(testdb.Ctx, forgotOTPHash, domain.OTPPurposeResetPassword)
	if err == nil {
		t.Fatal("Expected OTP to be soft-deleted after reset")
	}

	t.Log("Complete forgot and reset password flow successful")
}

// TestLogoutInvalidToken tests logout with an invalid token
// TestLogoutInvalidToken tests logout with an invalid token
func TestLogoutInvalidToken(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()

	// Try to logout with invalid token
	_, err := authService.Logout(testdb.Ctx, service.LogoutRequest{
		Token: "invalid-token",
	})

	if err == nil {
		t.Fatal("Expected error for invalid token")
	}

	if !domain.IsNotFound(err) {
		t.Fatalf("Expected NotFoundError, got: %T", err)
	}

	t.Log("Invalid token logout properly rejected")
}

// TestLogoutEmptyToken tests logout with empty token
func TestLogoutEmptyToken(t *testing.T) {
	testdb := CreateTestDB(t)

	authService := testdb.CreateAuthService()

	// Try to logout with empty token
	_, err := authService.Logout(testdb.Ctx, service.LogoutRequest{
		Token: "",
	})

	if err == nil {
		t.Fatal("Expected error for empty token")
	}

	if !domain.IsUnauthorized(err) {
		t.Fatalf("Expected UnauthorizedError, got: %T", err)
	}

	t.Log("Empty token logout properly rejected")
}
