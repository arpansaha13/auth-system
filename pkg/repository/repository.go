package repository

import (
	"gorm.io/gorm"

	irepo "github.com/arpansaha13/auth-system/internal/repository"
)

// Interfaces
type IUserRepository = irepo.IUserRepository
type IOTPRepository = irepo.IOTPRepository
type ISessionRepository = irepo.ISessionRepository

// Repository implementations
type UserRepository = irepo.UserRepository
type OTPRepository = irepo.OTPRepository
type SessionRepository = irepo.SessionRepository

// Constructors
func NewUserRepository(db *gorm.DB) IUserRepository {
	return irepo.NewUserRepository(db)
}

func NewOTPRepository(db *gorm.DB) IOTPRepository {
	return irepo.NewOTPRepository(db)
}

func NewSessionRepository(db *gorm.DB) ISessionRepository {
	return irepo.NewSessionRepository(db)
}
