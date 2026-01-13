package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
)

// TestGetUser retrieves user information by user ID
func TestGetUser(t *testing.T) {
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	t.Run("Get existing user successfully", func(t *testing.T) {
		user := createTestUserForUserTests(t, testdb, authService, "getuser@example.com", "password123")

		resp, err := authService.GetUser(testdb.Ctx, service.GetUserRequest{UserID: user.UserID})

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, user.UserID, resp.User.UserID)
		assert.Equal(t, "getuser@example.com", resp.User.Email)
		assert.True(t, resp.User.Verified)
	})

	t.Run("Get non-existing user", func(t *testing.T) {
		CleanupTables(t)

		resp, err := authService.GetUser(testdb.Ctx, service.GetUserRequest{UserID: 99999})

		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

// TestGetUserByEmail retrieves user information by email address
func TestGetUserByEmail(t *testing.T) {
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	t.Run("Get user by existing email", func(t *testing.T) {
		createTestUserForUserTests(t, testdb, authService, "getuserbyemail@example.com", "password123")

		resp, err := authService.GetUserByEmail(testdb.Ctx, service.GetUserByEmailRequest{Email: "getuserbyemail@example.com"})

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "getuserbyemail@example.com", resp.User.Email)
		assert.True(t, resp.User.Verified)
	})

	t.Run("Get user by non-existing email", func(t *testing.T) {
		CleanupTables(t)

		resp, err := authService.GetUserByEmail(testdb.Ctx, service.GetUserByEmailRequest{Email: "nonexistent@example.com"})

		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("Get user with empty email", func(t *testing.T) {
		CleanupTables(t)

		resp, err := authService.GetUserByEmail(testdb.Ctx, service.GetUserByEmailRequest{Email: ""})

		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

// TestDeleteUser deletes a user and all associated data
func TestDeleteUser(t *testing.T) {
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	t.Run("Delete existing user successfully", func(t *testing.T) {
		user := createTestUserForUserTests(t, testdb, authService, "deleteuser@example.com", "password123")

		resp, err := authService.DeleteUser(testdb.Ctx, service.DeleteUserRequest{UserID: user.UserID})

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "user deleted successfully", resp.Message)

		// Verify user is actually deleted
		verifyResp, verifyErr := authService.GetUser(testdb.Ctx, service.GetUserRequest{UserID: user.UserID})
		assert.Error(t, verifyErr)
		assert.Nil(t, verifyResp)
	})

	t.Run("Delete non-existing user", func(t *testing.T) {
		CleanupTables(t)

		resp, err := authService.DeleteUser(testdb.Ctx, service.DeleteUserRequest{UserID: 99999})

		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

// Helper function to create a test user
func createTestUserForUserTests(t *testing.T, testdb *TestDB, authService *service.AuthService, email, password string) *service.UserData {
	// Sign up
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	require.NotNil(t, signupResp)

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

	verifyResp, err := authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})
	require.NoError(t, err)
	require.NotNil(t, verifyResp)

	// Get user by email to retrieve the user ID
	getUserResp, err := authService.GetUserByEmail(testdb.Ctx, service.GetUserByEmailRequest{Email: email})
	require.NoError(t, err)
	require.NotNil(t, getUserResp)

	return &getUserResp.User
}
