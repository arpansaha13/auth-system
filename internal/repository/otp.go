package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/arpansaha13/auth-system/internal/domain"
	"gorm.io/gorm"
)

// OTPRepository handles OTP-related database operations
type OTPRepository struct {
	db *gorm.DB
}

// NewOTPRepository creates a new OTP repository
func NewOTPRepository(db *gorm.DB) *OTPRepository {
	return &OTPRepository{db: db}
}

// Create creates a new OTP record
func (r *OTPRepository) Create(ctx context.Context, otp *domain.OTP) error {
	return r.db.WithContext(ctx).Create(otp).Error
}

// GetByUserID retrieves OTP by user ID
func (r *OTPRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.OTP, error) {
	var otp domain.OTP
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		First(&otp).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &domain.NotFoundError{Message: "otp not found"}
		}
		return nil, &domain.InternalError{Message: "failed to get otp", Err: err}
	}

	return &otp, nil
}

// Delete removes an OTP record
func (r *OTPRepository) Delete(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&domain.OTP{}).Error
}

// DeleteExpired removes all expired OTP records
func (r *OTPRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&domain.OTP{}).Error
}
