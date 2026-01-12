package domain

import (
	"time"

	"gorm.io/gorm"
)

// User represents the users table
type User struct {
	ID        int64   `gorm:"primaryKey;autoIncrement"`
	Email     string  `gorm:"type:varchar(255);uniqueIndex;not null"`
	Username  *string `gorm:"type:varchar(100);uniqueIndex"`
	Verified  bool    `gorm:"default:false;not null"`
	LastLogin *time.Time
	CreatedAt time.Time

	// Relations
	Profile     *Profile     `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
	Credentials *Credentials `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
	OTP         *OTP         `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
	Sessions    []Session    `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName specifies the table name for the User model
func (User) TableName() string {
	return "users"
}

// Profile represents the profiles table (one-to-one)
type Profile struct {
	UserID    int64   `gorm:"primaryKey;references:ID"`
	FirstName *string `gorm:"type:varchar(100)"`
	LastName  *string `gorm:"type:varchar(100)"`

	// Relation
	User *User `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName specifies the table name for the Profile model
func (Profile) TableName() string {
	return "profiles"
}

// Credentials represents the credentials table (one-to-one)
type Credentials struct {
	UserID       int64  `gorm:"primaryKey;references:ID"`
	PasswordHash string `gorm:"type:varchar(255);not null"`

	// Relation
	User *User `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName specifies the table name for the Credentials model
func (Credentials) TableName() string {
	return "credentials"
}

// OTP represents the otps table (one-to-one)
type OTP struct {
	ID         int64      `gorm:"primaryKey;autoIncrement"`
	UserID     int64      `gorm:"not null;index"`
	OTPHash    string     `gorm:"type:varchar(255);uniqueIndex;not null"`
	HashedCode string     `gorm:"type:varchar(255);not null"`
	Purpose    int16      `gorm:"not null;default:1;index"`
	ExpiresAt  time.Time  `gorm:"not null"`
	DeletedAt  *time.Time `gorm:"type:timestamp with time zone" json:"deleted_at,omitempty"` // Soft delete
	CreatedAt  time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP"`

	// Relation
	User *User `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName specifies the table name for the OTP model
func (OTP) TableName() string {
	return "otps"
}

// Session represents the sessions table
type Session struct {
	ID        int64      `gorm:"primaryKey;autoIncrement"`
	UserID    int64      `gorm:"not null;index"`
	TokenHash string     `gorm:"type:varchar(255);uniqueIndex;not null"`
	ExpiresAt time.Time  `gorm:"not null"`
	DeletedAt *time.Time `gorm:"type:timestamp with time zone" json:"deleted_at,omitempty"` // Soft delete
	CreatedAt time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP"`

	// Relation
	User *User `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
}

// TableName specifies the table name for the Session model
func (Session) TableName() string {
	return "sessions"
}

// AutoMigrate runs auto migrations (should not be used - migrations are manual)
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&Profile{},
		&Credentials{},
		&OTP{},
		&Session{},
	)
}
