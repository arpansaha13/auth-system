package tests

import (
	"testing"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/service"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/pb"
	"google.golang.org/grpc/metadata"
)

// TestGetUser retrieves user information by user ID using gRPC
func TestGetUser(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	t.Run("Get existing user successfully", func(t *testing.T) {
		// Create and verify a test user
		user, token := createTestUserAndGetToken(t, testdb, authService, "getuser@example.com", "password123")

		// Add token to context
		md := metadata.Pairs("authorization", "Bearer "+token)
		ctxWithToken := metadata.NewOutgoingContext(ctx, md)

		// Call gRPC GetUser
		resp, err := client.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: user.UserId})

		if err != nil {
			t.Fatalf("GetUser failed: %v", err)
		}
		if resp.User == nil {
			t.Fatal("Expected user in response")
		}
		if resp.User.UserId != user.UserId {
			t.Fatalf("Expected user ID %d, got %d", user.UserId, resp.User.UserId)
		}
		if resp.User.Email != "getuser@example.com" {
			t.Fatalf("Expected email 'getuser@example.com', got %s", resp.User.Email)
		}
		if !resp.User.Verified {
			t.Fatal("Expected user to be verified")
		}
	})
}

// TestGetUserByEmail retrieves user information by email address using gRPC
func TestGetUserByEmail(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	t.Run("Get user by existing email", func(t *testing.T) {
		// Create and verify a test user
		_, token := createTestUserAndGetToken(t, testdb, authService, "getuserbyemail@example.com", "password123")

		// Add token to context
		md := metadata.Pairs("authorization", "Bearer "+token)
		ctxWithToken := metadata.NewOutgoingContext(ctx, md)

		// Call gRPC GetUserByEmail
		resp, err := client.GetUserByEmail(ctxWithToken, &pb.GetUserByEmailRequest{Email: "getuserbyemail@example.com"})

		if err != nil {
			t.Fatalf("GetUserByEmail failed: %v", err)
		}
		if resp.User == nil {
			t.Fatal("Expected user in response")
		}
		if resp.User.Email != "getuserbyemail@example.com" {
			t.Fatalf("Expected email 'getuserbyemail@example.com', got %s", resp.User.Email)
		}
		if !resp.User.Verified {
			t.Fatal("Expected user to be verified")
		}
	})
}

// TestDeleteUser deletes a user and all associated data using gRPC
func TestDeleteUser(t *testing.T) {
	CleanupTables(t)
	client := GetGRPCClient()
	ctx := GetTestContext()
	testdb := CreateTestDB(t)
	authService := testdb.CreateAuthService()

	t.Run("Delete existing user successfully", func(t *testing.T) {
		// Create and verify a test user
		user, token := createTestUserAndGetToken(t, testdb, authService, "deleteuser@example.com", "password123")

		// Add token to context
		md := metadata.Pairs("authorization", "Bearer "+token)
		ctxWithToken := metadata.NewOutgoingContext(ctx, md)

		// Call gRPC DeleteUser
		resp, err := client.DeleteUser(ctxWithToken, &pb.DeleteUserRequest{UserId: user.UserId})

		if err != nil {
			t.Fatalf("DeleteUser failed: %v", err)
		}
		if resp.Message == "" {
			t.Fatal("Expected message in response")
		}

		// Verify user is actually deleted by trying to get them
		_, verifyErr := client.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: user.UserId})
		if verifyErr == nil {
			t.Fatal("Expected error when getting deleted user")
		}
	})
}

// Helper function to create a test user and get session token
func createTestUserAndGetToken(t *testing.T, testdb *TestDB, authService *service.AuthService, email, password string) (*pb.UserData, string) {
	// Sign up
	signupResp, err := authService.Signup(testdb.Ctx, service.SignupRequest{
		Email:    email,
		Password: password,
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

	_, verifyErr := authService.VerifyOTP(testdb.Ctx, service.VerifyOTPRequest{
		OTPHash: otpHash,
		Code:    testOTP,
	})
	if verifyErr != nil {
		t.Fatalf("VerifyOTP failed: %v", verifyErr)
	}

	// Get user by email to retrieve the user ID
	getUserResp, err := authService.GetUserByEmail(testdb.Ctx, service.GetUserByEmailRequest{Email: email})
	if err != nil {
		t.Fatalf("GetUserByEmail failed: %v", err)
	}

	// Create session token (just use the session token from verification)
	// We need to get the session token from login
	loginResp, err := authService.Login(testdb.Ctx, service.LoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	user := &pb.UserData{
		UserId:   getUserResp.User.UserID,
		Email:    getUserResp.User.Email,
		Username: getUserResp.User.Username,
		Verified: getUserResp.User.Verified,
	}

	return user, loginResp.SessionToken
}
