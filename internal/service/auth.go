package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/arpansaha13/auth-system/internal/domain"
	"github.com/arpansaha13/auth-system/internal/repository"
	"github.com/arpansaha13/auth-system/internal/utils"
	"github.com/arpansaha13/auth-system/internal/worker"
)

// AuthService handles authentication business logic
type AuthService struct {
	userRepo    *repository.UserRepository
	otpRepo     *repository.OTPRepository
	sessionRepo *repository.SessionRepository
	hasher      *utils.PasswordHasher
	validator   *utils.Validator
	config      AuthServiceConfig
}

// AuthServiceConfig holds configuration for the auth service
type AuthServiceConfig struct {
	OTPExpiry  time.Duration
	OTPLength  int
	SessionTTL time.Duration
	SecretKey  string
	EmailPool  *worker.EmailWorkerPool
}

// NewAuthService creates a new auth service
func NewAuthService(
	userRepo *repository.UserRepository,
	otpRepo *repository.OTPRepository,
	sessionRepo *repository.SessionRepository,
	hasher *utils.PasswordHasher,
	validator *utils.Validator,
	config AuthServiceConfig,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		otpRepo:     otpRepo,
		sessionRepo: sessionRepo,
		hasher:      hasher,
		validator:   validator,
		config:      config,
	}
}

// SignupRequest represents signup input
type SignupRequest struct {
	Email    string
	Password string
}

// SignupResponse represents signup output
type SignupResponse struct {
	Message string
	UserID  string
}

// Signup handles user registration with OTP email dispatch
func (s *AuthService) Signup(ctx context.Context, req SignupRequest) (*SignupResponse, error) {
	// Validate input
	if err := s.validator.ValidateEmail(req.Email); err != nil {
		return nil, &domain.ValidationError{Message: "invalid email format", Field: "email"}
	}

	if err := s.validator.ValidatePassword(req.Password); err != nil {
		return nil, &domain.ValidationError{Message: "password must be at least 8 characters", Field: "password"}
	}

	// Check if email already exists
	exists, err := s.userRepo.ExistsEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, &domain.ConflictError{Message: "email already registered"}
	}

	// Hash password
	passwordHash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, &domain.InternalError{Message: "failed to process password", Err: err}
	}

	// Create user and credentials in transaction
	newUser := &domain.User{
		Email:    req.Email,
		Verified: false,
	}

	credentials := &domain.Credentials{
		PasswordHash: passwordHash,
	}

	if err := s.userRepo.Create(ctx, newUser, credentials); err != nil {
		return nil, &domain.InternalError{Message: "failed to create user", Err: err}
	}

	// Generate and send OTP
	otp, err := utils.GenerateOTP(s.config.OTPLength)
	if err != nil {
		return nil, &domain.InternalError{Message: "failed to generate otp", Err: err}
	}

	otpHash, err := s.hasher.Hash(otp)
	if err != nil {
		return nil, &domain.InternalError{Message: "failed to process otp", Err: err}
	}

	otpRecord := &domain.OTP{
		UserID:     newUser.ID,
		HashedCode: otpHash,
		ExpiresAt:  time.Now().Add(s.config.OTPExpiry),
	}

	if err := s.otpRepo.Create(ctx, otpRecord); err != nil {
		return nil, &domain.InternalError{Message: "failed to store otp", Err: err}
	}

	// Enqueue email task with OTP details
	emailBody := fmt.Sprintf("Your OTP is: %s\n\nThis code expires in 10 minutes.", otp)
	s.config.EmailPool.Enqueue(worker.EmailTask{
		Recipient: req.Email,
		Subject:   "Verify Your Email",
		Body:      emailBody,
	})

	return &SignupResponse{
		Message: "signup successful, check your email for otp",
		UserID:  newUser.ID.String(),
	}, nil
}

// VerifyOTPRequest represents OTP verification input
type VerifyOTPRequest struct {
	UserID string
	Code   string
}

// VerifyOTPResponse represents OTP verification output
type VerifyOTPResponse struct {
	Message      string
	Username     string
	SessionToken string
}

// VerifyOTP verifies OTP and marks user as verified
func (s *AuthService) VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*VerifyOTPResponse, error) {
	// Validate input
	if err := s.validator.ValidateOTPCode(req.Code, s.config.OTPLength); err != nil {
		return nil, &domain.ValidationError{Message: "invalid otp format", Field: "code"}
	}

	// Parse user ID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return nil, &domain.ValidationError{Message: "invalid user id format", Field: "user_id"}
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Check if already verified
	if user.Verified {
		return nil, &domain.ValidationError{Message: "user already verified", Field: ""}
	}

	// Get OTP
	otpRecord, err := s.otpRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Check expiry
	if time.Now().After(otpRecord.ExpiresAt) {
		return nil, &domain.UnauthorizedError{Message: "otp has expired"}
	}

	// Verify OTP hash
	if !s.hasher.Verify(otpRecord.HashedCode, req.Code) {
		return nil, &domain.UnauthorizedError{Message: "invalid otp code"}
	}

	// Generate username with retry logic
	emailPrefix := utils.GetEmailPrefix(user.Email)
	username, err := s.generateUniqueUsername(ctx, emailPrefix)
	if err != nil {
		return nil, err
	}

	// Update user as verified and set username in transaction
	if err := s.userRepo.UpdateVerified(ctx, userID, username); err != nil {
		return nil, &domain.InternalError{Message: "failed to update user", Err: err}
	}

	// Delete OTP
	if err := s.otpRepo.Delete(ctx, userID); err != nil {
		return nil, &domain.InternalError{Message: "failed to clean up otp", Err: err}
	}

	// Create session
	sessionToken, err := utils.GenerateToken(32)
	if err != nil {
		return nil, &domain.InternalError{Message: "failed to generate session token", Err: err}
	}

	tokenHash := s.hashToken(sessionToken)
	session := &domain.Session{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(s.config.SessionTTL),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, &domain.InternalError{Message: "failed to create session", Err: err}
	}

	return &VerifyOTPResponse{
		Message:      "otp verified successfully",
		Username:     username,
		SessionToken: sessionToken,
	}, nil
}

// LoginRequest represents login input
type LoginRequest struct {
	Email    string
	Password string
}

// LoginResponse represents login output
type LoginResponse struct {
	SessionToken string
	ExpiresAt    time.Time
}

// Login authenticates user with email and password
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	// Validate input
	if err := s.validator.ValidateEmail(req.Email); err != nil {
		return nil, &domain.ValidationError{Message: "invalid email", Field: "email"}
	}

	// Get user
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if domain.IsNotFound(err) {
			return nil, &domain.UnauthorizedError{Message: "invalid email or password"}
		}
		return nil, err
	}

	// Check if verified
	if !user.Verified {
		return nil, &domain.UnauthorizedError{Message: "email not verified"}
	}

	// Verify password
	if user.Credentials == nil || !s.hasher.Verify(user.Credentials.PasswordHash, req.Password) {
		return nil, &domain.UnauthorizedError{Message: "invalid email or password"}
	}

	// Update last login
	_ = s.userRepo.UpdateLastLogin(ctx, user.ID)

	// Create session
	sessionToken, err := utils.GenerateToken(32)
	if err != nil {
		return nil, &domain.InternalError{Message: "failed to generate session token", Err: err}
	}

	tokenHash := s.hashToken(sessionToken)
	expiresAt := time.Now().Add(s.config.SessionTTL)

	session := &domain.Session{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, &domain.InternalError{Message: "failed to create session", Err: err}
	}

	return &LoginResponse{
		SessionToken: sessionToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// ValidateSessionRequest represents session validation input
type ValidateSessionRequest struct {
	Token string
}

// ValidateSessionResponse represents session validation output
type ValidateSessionResponse struct {
	UserID string
	Valid  bool
}

// ValidateSession validates a session token
func (s *AuthService) ValidateSession(ctx context.Context, req ValidateSessionRequest) (*ValidateSessionResponse, error) {
	if req.Token == "" {
		return &ValidateSessionResponse{Valid: false}, nil
	}

	tokenHash := s.hashToken(req.Token)
	valid, userID, err := s.sessionRepo.IsTokenValid(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	return &ValidateSessionResponse{
		UserID: userID.String(),
		Valid:  valid,
	}, nil
}

// RefreshSessionRequest represents session refresh input
type RefreshSessionRequest struct {
	Token string
}

// RefreshSessionResponse represents session refresh output
type RefreshSessionResponse struct {
	NewSessionToken string
}

// RefreshSession extends a valid session token
func (s *AuthService) RefreshSession(ctx context.Context, req RefreshSessionRequest) (*RefreshSessionResponse, error) {
	if req.Token == "" {
		return nil, &domain.UnauthorizedError{Message: "invalid token"}
	}

	tokenHash := s.hashToken(req.Token)
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	// Check if session is still valid
	if time.Now().After(session.ExpiresAt) {
		return nil, &domain.UnauthorizedError{Message: "session expired"}
	}

	// Generate new token
	newToken, err := utils.GenerateToken(32)
	if err != nil {
		return nil, &domain.InternalError{Message: "failed to generate new token", Err: err}
	}

	newTokenHash := s.hashToken(newToken)
	session.TokenHash = newTokenHash
	session.ExpiresAt = time.Now().Add(s.config.SessionTTL)

	if err := s.sessionRepo.Update(ctx, session); err != nil {
		return nil, &domain.InternalError{Message: "failed to update session", Err: err}
	}

	return &RefreshSessionResponse{
		NewSessionToken: newToken,
	}, nil
}

// Private helper methods

func (s *AuthService) generateUniqueUsername(ctx context.Context, emailPrefix string) (string, error) {
	const maxRetries = 10

	for i := 0; i < maxRetries; i++ {
		username, err := utils.GenerateUsername(emailPrefix, 1)
		if err != nil {
			return "", err
		}

		exists, err := s.userRepo.ExistsUsername(ctx, username)
		if err != nil {
			return "", err
		}

		if !exists {
			return username, nil
		}
	}

	return "", &domain.InternalError{
		Message: fmt.Sprintf("failed to generate unique username after %d retries", maxRetries),
	}
}

func (s *AuthService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token + s.config.SecretKey))
	return hex.EncodeToString(hash[:])
}
