package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/internal/worker"
)

// AuthE2ETestSuite is a test suite for end-to-end auth flows
type AuthE2ETestSuite struct {
	BaseTestSuite
}

// SetupTest prepares each test
func (s *AuthE2ETestSuite) SetupTest() {
	s.CleanupTablesForSuite()
}

// CreateTestDB creates a test database connection using shared global resources
func (s *AuthE2ETestSuite) CreateTestDB() *TestDB {
	// Tables should already be cleaned by SetupTest
	return &TestDB{
		DB:  s.DB,
		Ctx: s.Ctx,
	}
}

// CreateAuthService creates an auth service for testing
func (tdb *TestDB) CreateAuthService() *service.AuthService {
	userRepo := repository.NewUserRepository(tdb.DB)
	otpRepo := repository.NewOTPRepository(tdb.DB)
	sessionRepo := repository.NewSessionRepository(tdb.DB)
	hasher := utils.NewPasswordHasher()
	emailProvider := worker.NewMockEmailProvider()

	// Create email worker pool with 2 workers for testing
	emailPool := worker.NewEmailWorkerPool(2, 50, emailProvider)

	return service.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		hasher,
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
func (s *AuthE2ETestSuite) TestSignupFlow() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()

	// Test signup
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	s.Require().NoError(err)
	s.Require().NotEmpty(signupResp.OTPHash, "Expected OTP hash in response")
	s.Require().NotEmpty(signupResp.Message, "Expected message in response")

	s.T().Logf("Signup successful: %s, OTP Hash: %s", signupResp.Message, signupResp.OTPHash)
}

// TestSignupDuplicate tests duplicate email prevention
func (s *AuthE2ETestSuite) TestSignupDuplicate() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()

	// First signup
	_, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	s.Require().NoError(err)

	// Duplicate signup
	_, err = authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "anotherPassword123",
	})

	s.Require().Error(err, "Expected error for duplicate email")
	s.Require().True(domain.IsConflict(err), "Expected ConflictError")

	s.T().Logf("Duplicate signup correctly prevented: %v", err)
}

// TestLoginBeforeVerification tests that login fails before email verification
func (s *AuthE2ETestSuite) TestLoginBeforeVerification() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()

	// Signup
	_, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	s.Require().NoError(err)

	// Try to login before verification
	_, err = authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	s.Require().Error(err, "Expected error when logging in before email verification")
	s.Require().True(domain.IsUnauthorized(err), "Expected UnauthorizedError")

	s.T().Logf("Login correctly blocked before verification: %v", err)
}

// TestCompleteAuthFlow tests the complete authentication flow
func (s *AuthE2ETestSuite) TestCompleteAuthFlow() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()
	otpRepo := repository.NewOTPRepository(testdb.DB)

	// Step 1: Signup
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	s.Require().NoError(err)

	otpHash := signupResp.OTPHash

	s.Require().NotEmpty(otpHash, "Expected OTP hash in signup response")

	// Step 2: Get OTP from database (simulate email)
	_, err = otpRepo.GetByOTPHash(testdb.Ctx, otpHash, domain.OTPPurposeSignupVerification)
	s.Require().NoError(err)

	// For testing, we need to update the OTP code hash
	hasher := utils.NewPasswordHasher()
	testOTP := "123456"
	hash, _ := hasher.Hash(testOTP)
	s.Require().NoError(testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", hash).Error)

	// Step 3: Verify OTP using OTP hash from signup response
	verifyResp, err := authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})

	s.Require().NoError(err)
	s.Require().NotEmpty(verifyResp.SessionToken, "Expected session token in verification response")
	s.Require().NotEmpty(verifyResp.OTPHash, "Expected OTP hash in verification response")

	s.T().Logf("OTP verified, username: %s, OTP hash: %s", verifyResp.Username, verifyResp.OTPHash)

	// Step 4: Login
	loginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	s.Require().NoError(err)
	s.Require().NotEmpty(loginResp.SessionToken, "Expected session token in login response")

	// Step 5: Validate session
	validateResp, err := authService.ValidateSession(testdb.Ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})

	s.Require().NoError(err)
	s.Require().True(validateResp.Valid, "Expected session to be valid")

	s.T().Log("Complete auth flow successful")
}

// TestSessionRefresh tests session refresh
func (s *AuthE2ETestSuite) TestSessionRefresh() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()

	// Complete signup, verify OTP, and login flow to get a valid session
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "refresh-test@example.com",
		Password: "password123",
	})
	s.Require().NoError(err)

	otpHash := signupResp.OTPHash

	// Prepare and verify OTP
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	s.Require().NoError(testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode).Error)

	_, err = authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})
	s.Require().NoError(err)

	// Login to get a valid session token
	loginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "refresh-test@example.com",
		Password: "password123",
	})
	s.Require().NoError(err)

	oldToken := loginResp.SessionToken

	// Test refresh with valid token
	refreshResp, err := authService.RefreshSession(testdb.Ctx, service.RefreshSessionRequest{
		Token: oldToken,
	})

	s.Require().NoError(err)
	s.Require().NotEmpty(refreshResp.NewSessionToken, "Expected new session token")
	s.Require().NotEqual(oldToken, refreshResp.NewSessionToken, "Expected different token after refresh")

	s.T().Log("Session refresh successful")
}

// TestLogout tests the logout functionality
func (s *AuthE2ETestSuite) TestLogout() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()

	// Step 1: Signup
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "logout-test@example.com",
		Password: "password123",
	})
	s.Require().NoError(err)

	otpHash := signupResp.OTPHash

	// Step 2: Prepare and verify OTP
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTP)
	s.Require().NoError(testdb.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", otpHash).
		Update("hashed_code", otpHashCode).Error)

	// Step 3: Verify OTP
	_, err = authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})
	s.Require().NoError(err)

	// Step 4: Login
	loginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "logout-test@example.com",
		Password: "password123",
	})
	s.Require().NoError(err)

	// Step 5: Verify session is valid before logout
	validateResp, err := authService.ValidateSession(testdb.Ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})
	s.Require().NoError(err)
	s.Require().True(validateResp.Valid, "Expected session to be valid before logout")

	// Step 6: Logout
	logoutResp, err := authService.Logout(testdb.Ctx, service.LogoutRequest{
		Token: loginResp.SessionToken,
	})
	s.Require().NoError(err)
	s.Require().Equal("logout successful", logoutResp.Message)

	// Step 7: Verify session is invalid after logout
	validateAfterLogout, err := authService.ValidateSession(testdb.Ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})
	s.Require().NoError(err)
	s.Require().False(validateAfterLogout.Valid, "Expected session to be invalid after logout")

	s.T().Log("Logout successful and session invalidated")
}

// TestForgotAndResetPasswordFlow tests the complete forgot and reset password flow
func (s *AuthE2ETestSuite) TestForgotAndResetPasswordFlow() {
	testdb := s.CreateTestDB()
	authService := testdb.CreateAuthService()
	otpRepo := repository.NewOTPRepository(testdb.DB)

	// Step 1: Signup and verify user
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    "reset-flow@example.com",
		Password: "oldPassword123",
	})
	s.Require().NoError(err)

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
	s.Require().NoError(err)

	// Step 2: Initiate forgot password
	forgotResp, err := authService.ForgotPassword(testdb.Ctx, service.ForgotPasswordRequest{
		Email: "reset-flow@example.com",
	})
	s.Require().NoError(err)

	forgotOTPHash := forgotResp.OTPHash
	s.Require().NotEmpty(forgotOTPHash, "Expected OTP hash from forgot password")

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
	s.Require().NoError(err)
	s.Require().Equal("password reset successfully", resetResp.Message)

	// Step 5: Verify old password no longer works
	_, err = authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "reset-flow@example.com",
		Password: "oldPassword123",
	})
	s.Require().Error(err, "Expected login to fail with old password")

	// Step 6: Verify new password works
	newLoginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    "reset-flow@example.com",
		Password: "newPassword123",
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(newLoginResp.SessionToken, "Expected session token from new login")

	// Step 7: Verify OTP is soft-deleted after reset
	_, err = otpRepo.GetByOTPHash(testdb.Ctx, forgotOTPHash, domain.OTPPurposeResetPassword)
	s.Require().Error(err, "Expected OTP to be soft-deleted after reset")

	s.T().Log("Complete forgot and reset password flow successful")
}

// TestLogoutInvalidToken tests logout with an invalid token
// TestLogoutInvalidToken tests logout with an invalid token
func (s *AuthE2ETestSuite) TestLogoutInvalidToken() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()

	// Try to logout with invalid token
	_, err := authService.Logout(testdb.Ctx, service.LogoutRequest{
		Token: "invalid-token",
	})

	s.Require().Error(err, "Expected error for invalid token")
	s.Require().True(domain.IsNotFound(err), "Expected NotFoundError")

	s.T().Log("Invalid token logout properly rejected")
}

// TestLogoutEmptyToken tests logout with empty token
func (s *AuthE2ETestSuite) TestLogoutEmptyToken() {
	testdb := s.CreateTestDB()

	authService := testdb.CreateAuthService()

	// Try to logout with empty token
	_, err := authService.Logout(testdb.Ctx, service.LogoutRequest{
		Token: "",
	})

	s.Require().Error(err, "Expected error for empty token")
	s.Require().True(domain.IsUnauthorized(err), "Expected UnauthorizedError")

	s.T().Log("Empty token logout properly rejected")
}

// TestAuthE2E runs the end-to-end authentication test suite
func TestAuthE2E(t *testing.T) {
	suite.Run(t, new(AuthE2ETestSuite))
}
