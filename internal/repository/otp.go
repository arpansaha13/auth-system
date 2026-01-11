package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/arpansaha13/auth-system/internal/domain"
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

// GetByUserID retrieves OTP by user ID (excludes soft-deleted)
func (r *OTPRepository) GetByUserID(ctx context.Context, userID int64) (*domain.OTP, error) {
	var otp domain.OTP
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		First(&otp).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &domain.NotFoundError{Message: "otp not found"}
		}
		return nil, &domain.InternalError{Message: "failed to get otp", Err: err}
	}

	return &otp, nil
}

// SoftDelete soft-deletes an OTP record
func (r *OTPRepository) SoftDelete(ctx context.Context, userID int64) error {
	return r.db.WithContext(ctx).
		Model(&domain.OTP{}).
		Where("user_id = ?", userID).
		Update("deleted_at", time.Now()).Error
}

// DeleteExpiredAndSoftDeleted physically deletes expired and soft-deleted OTPs
func (r *OTPRepository) DeleteExpiredAndSoftDeleted(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ? OR deleted_at IS NOT NULL", time.Now()).
		Delete(&domain.OTP{}).Error
}
