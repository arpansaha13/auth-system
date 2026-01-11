package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/internal/worker"
	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

	if signupResp.UserID == "" {
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

	userID := uuid.MustParse(signupResp.UserID)

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
		UserID: userID.String(),
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

	if validateResp.UserID != userID.String() {
		t.Fatalf("Expected user ID %s, got %s", userID.String(), validateResp.UserID)
	}

	t.Log("Complete auth flow successful")
}

// TestSessionRefresh tests session refresh
func TestSessionRefresh(t *testing.T) {
	ctx := context.Background()
	testdb := SetupTestDB(ctx, t)
	defer testdb.Cleanup(t)

	authService := testdb.CreateAuthService()

	// Create a user manually for testing
	user := &domain.User{
		Email:    "test@example.com",
		Verified: true,
	}
	if err := testdb.DB.Create(user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a session
	oldToken := "test-token-12345678901234567890"
	_ = oldToken // oldToken used for reference

	_, _ = authService.Login(ctx, service.LoginRequest{
		Email:    "test@example.com",
		Password: "somePassword",
	})

	// This will fail because credentials don't exist
	// Let's create credentials first
	creds := &domain.Credentials{
		UserID:       user.ID,
		PasswordHash: "ignored",
	}
	if createErr := testdb.DB.Create(creds).Error; createErr != nil {
		t.Fatalf("Failed to create credentials: %v", createErr)
	}

	// Try again - this will still fail because password won't match
	// For this test, let's just verify the refresh logic with an existing session
	session := &domain.Session{
		UserID:    user.ID,
		TokenHash: oldToken,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	if err := testdb.DB.Create(session).Error; err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Test refresh
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
