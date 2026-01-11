package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/arpansaha13/auth-system/internal/domain"
	"gorm.io/gorm"
)

// SessionRepository handles session-related database operations
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create creates a new session
func (r *SessionRepository) Create(ctx context.Context, session *domain.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

// GetByTokenHash retrieves a session by token hash
func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var session domain.Session
	err := r.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		First(&session).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &domain.NotFoundError{Message: "session not found"}
		}
		return nil, &domain.InternalError{Message: "failed to get session", Err: err}
	}

	return &session, nil
}

// GetByUserID retrieves all valid sessions for a user
func (r *SessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	var sessions []domain.Session
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Find(&sessions).Error

	if err != nil {
		return nil, &domain.InternalError{Message: "failed to get sessions", Err: err}
	}

	return sessions, nil
}

// Update updates a session
func (r *SessionRepository) Update(ctx context.Context, session *domain.Session) error {
	return r.db.WithContext(ctx).Save(session).Error
}

// Delete removes a session
func (r *SessionRepository) Delete(ctx context.Context, sessionID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("id = ?", sessionID).
		Delete(&domain.Session{}).Error
}

// DeleteExpired removes all expired sessions
func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&domain.Session{}).Error
}

// DeleteByUserID removes all sessions for a user
func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&domain.Session{}).Error
}

// IsTokenValid checks if a token is valid (exists and not expired)
func (r *SessionRepository) IsTokenValid(ctx context.Context, tokenHash string) (bool, uuid.UUID, error) {
	var session domain.Session
	err := r.db.WithContext(ctx).
		Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).
		First(&session).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, uuid.UUID{}, nil
		}
		return false, uuid.UUID{}, &domain.InternalError{Message: "failed to validate token", Err: err}
	}

	return true, session.UserID, nil
}
