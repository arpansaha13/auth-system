package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"github.com/google/uuid"

	"github.com/arpansaha13/auth-system/internal/domain"
)

// UserRepository handles user-related database operations
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user and associated records in a transaction
func (r *UserRepository) Create(ctx context.Context, user *domain.User, credentials *domain.Credentials) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Create user
		if err := tx.Create(user).Error; err != nil {
			return err
		}

		// Create credentials
		credentials.UserID = user.ID
		if err := tx.Create(credentials).Error; err != nil {
			return err
		}

		// Create empty profile
		profile := &domain.Profile{UserID: user.ID}
		if err := tx.Create(profile).Error; err != nil {
			return err
		}

		return nil
	})
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Preload("Credentials").
		Preload("OTP").
		Preload("Profile").
		Where("email = ?", email).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &domain.NotFoundError{Message: "user not found"}
		}
		return nil, &domain.InternalError{Message: "failed to get user", Err: err}
	}

	return &user, nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Preload("Credentials").
		Preload("OTP").
		Preload("Profile").
		Where("id = ?", userID).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &domain.NotFoundError{Message: "user not found"}
		}
		return nil, &domain.InternalError{Message: "failed to get user", Err: err}
	}

	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Preload("Credentials").
		Preload("OTP").
		Preload("Profile").
		Where("username = ?", username).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &domain.NotFoundError{Message: "user not found"}
		}
		return nil, &domain.InternalError{Message: "failed to get user", Err: err}
	}

	return &user, nil
}

// UpdateVerified marks a user as verified and sets their username
func (r *UserRepository) UpdateVerified(ctx context.Context, userID uuid.UUID, username string) error {
	return r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"verified": true,
			"username": username,
		}).Error
}

// UpdateLastLogin updates the user's last login timestamp
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("id = ?", userID).
		Update("last_login", now).Error
}

// ExistsUsername checks if a username already exists
func (r *UserRepository) ExistsUsername(ctx context.Context, username string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("username = ?", username).
		Count(&count).Error

	if err != nil {
		return false, &domain.InternalError{Message: "failed to check username", Err: err}
	}

	return count > 0, nil
}

// ExistsEmail checks if an email already exists
func (r *UserRepository) ExistsEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("email = ?", email).
		Count(&count).Error

	if err != nil {
		return false, &domain.InternalError{Message: "failed to check email", Err: err}
	}

	return count > 0, nil
}
