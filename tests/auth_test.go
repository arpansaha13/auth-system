package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/internal/worker"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestDB holds database resources for tests
type TestDB struct {
	DB        *gorm.DB
	Container testcontainers.Container
	Ctx       context.Context
}

// SetupTestDB creates a test database using Testcontainers
func SetupTestDB(ctx context.Context, t *testing.T) *TestDB {
	// Request a PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "test_auth",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start container: %v", err)
	}

	// Get the container's host and port
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to get host: %v", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to get port: %v", err)
	}

	// Connect to the database
	dsn := fmt.Sprintf(
		"host=%s port=%s user=testuser password=testpass dbname=test_auth sslmode=disable",
		host, port.Port(),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Run migrations
	if err := domain.AutoMigrate(db); err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return &TestDB{
		DB:        db,
		Container: container,
		Ctx:       ctx,
	}
}

// Cleanup closes the database connection and stops the container
func (tdb *TestDB) Cleanup(t *testing.T) {
	if tdb.Container != nil {
		if err := tdb.Container.Terminate(tdb.Ctx); err != nil {
			t.Logf("Warning: Failed to terminate container: %v", err)
		}
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
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// Test signup
	signupResp, err := authService.Signup(ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	if signupResp.UserID == 0 {
		t.Fatal("Expected user ID in response")
	}

	if signupResp.Message == "" {
		t.Fatal("Expected message in response")
	}

	t.Logf("Signup successful: %s", signupResp.Message)
}

// TestSignupDuplicate tests duplicate email prevention
func TestSignupDuplicate(t *testing.T) {
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// First signup
	_, err := authService.Signup(ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("First signup failed: %v", err)
	}

	// Duplicate signup
	_, err = authService.Signup(ctx, service.SignupRequest{
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
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// Signup
	_, err := authService.Signup(ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	// Try to login before verification
	_, err = authService.Login(ctx, service.LoginRequest{
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
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()
	otpRepo := repository.NewOTPRepository(testdb.DB)

	// Step 1: Signup
	signupResp, err := authService.Signup(ctx, service.SignupRequest{
		Email:    "test@example.com",
		Password: "securePassword123",
	})

	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	userID := signupResp.UserID

	// Step 2: Get OTP from database (simulate email)
	otp, err := otpRepo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to get OTP: %v", err)
	}

	// For testing, we need to get the actual OTP code
	// In real scenario, this would come from email
	// Let's verify with correct code format
	hasher := utils.NewPasswordHasher()

	// Generate a test OTP that matches the hash
	testOTP := "123456"
	if err := testdb.DB.Model(&domain.OTP{}).
		Where("user_id = ?", userID).
		Update("hashed_code", "").Error; err != nil {
		t.Fatalf("Failed to clear hash: %v", err)
	}

	// Hash the test OTP
	hash, _ := hasher.Hash(testOTP)
	if err := testdb.DB.Model(&domain.OTP{}).
		Where("user_id = ?", userID).
		Update("hashed_code", hash).Error; err != nil {
		t.Fatalf("Failed to set hash: %v", err)
	}

	// Step 3: Verify OTP
	verifyResp, err := authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		UserID: userID,
		Code:   testOTP,
	})

	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}

	if verifyResp.SessionToken == "" {
		t.Fatal("Expected session token in verification response")
	}

	t.Logf("OTP verified, username: %s", verifyResp.Username)

	_ = otp // otp is used for OTP retrieval validation

	// Step 4: Login
	loginResp, err := authService.Login(ctx, service.LoginRequest{
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
	validateResp, err := authService.ValidateSession(ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})

	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}

	if !validateResp.Valid {
		t.Fatal("Expected session to be valid")
	}

	if validateResp.UserID != userID {
		t.Fatalf("Expected user ID %d, got %d", userID, validateResp.UserID)
	}

	t.Log("Complete auth flow successful")
}

// TestSessionRefresh tests session refresh
func TestSessionRefresh(t *testing.T) {
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// Complete signup, verify OTP, and login flow to get a valid session
	signupResp, err := authService.Signup(ctx, service.SignupRequest{
		Email:    "refresh-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	userID := signupResp.UserID

	// Prepare and verify OTP
	otpRecord := &domain.OTP{}
	testdb.DB.Where("user_id = ?", userID).First(otpRecord)
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHash, _ := hasher.Hash(testOTP)
	testdb.DB.Model(otpRecord).Update("hashed_code", otpHash)

	_, err = authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		UserID: userID,
		Code:   testOTP,
	})
	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}

	// Login to get a valid session token
	loginResp, err := authService.Login(ctx, service.LoginRequest{
		Email:    "refresh-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	oldToken := loginResp.SessionToken

	// Test refresh with valid token
	refreshResp, err := authService.RefreshSession(ctx, service.RefreshSessionRequest{
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
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// Step 1: Signup
	signupResp, err := authService.Signup(ctx, service.SignupRequest{
		Email:    "logout-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	userID := signupResp.UserID

	// Step 2: Get OTP from database
	otpRecord := &domain.OTP{}
	if err := testdb.DB.Where("user_id = ?", userID).First(otpRecord).Error; err != nil {
		t.Fatalf("Failed to get OTP: %v", err)
	}

	// Generate test OTP that will match the hash
	testOTP := "123456"
	hasher := utils.NewPasswordHasher()
	otpHash, _ := hasher.Hash(testOTP)
	testdb.DB.Model(otpRecord).Update("hashed_code", otpHash)

	// Step 3: Verify OTP
	_, err = authService.VerifyOTP(ctx, service.VerifyOTPRequest{
		UserID: userID,
		Code:   testOTP,
	})
	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}

	// Step 4: Login
	loginResp, err := authService.Login(ctx, service.LoginRequest{
		Email:    "logout-test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Step 5: Verify session is valid before logout
	validateResp, err := authService.ValidateSession(ctx, service.ValidateSessionRequest{
		Token: loginResp.SessionToken,
	})
	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}

	if !validateResp.Valid {
		t.Fatal("Expected session to be valid before logout")
	}

	// Step 6: Logout
	logoutResp, err := authService.Logout(ctx, service.LogoutRequest{
		Token: loginResp.SessionToken,
	})
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	if logoutResp.Message != "logout successful" {
		t.Fatalf("Expected logout success message, got: %s", logoutResp.Message)
	}

	// Step 7: Verify session is invalid after logout
	validateAfterLogout, err := authService.ValidateSession(ctx, service.ValidateSessionRequest{
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

// TestLogoutInvalidToken tests logout with an invalid token
func TestLogoutInvalidToken(t *testing.T) {
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// Try to logout with invalid token
	_, err := authService.Logout(ctx, service.LogoutRequest{
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
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// Try to logout with empty token
	_, err := authService.Logout(ctx, service.LogoutRequest{
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
