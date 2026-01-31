package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateStructs(t *testing.T) {
	v := NewValidator()

	t.Run("SignupPayload", func(t *testing.T) {
		tests := []struct {
			name    string
			payload SignupPayload
			wantErr bool
		}{
			{"Valid payload", SignupPayload{Email: "test@example.com", Password: "password123"}, false},
			{"Invalid email", SignupPayload{Email: "wrong-email", Password: "password123"}, true},
			{"Password too short", SignupPayload{Email: "test@example.com", Password: "123"}, true},
			{"Missing fields", SignupPayload{}, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := v.Validate(tt.payload)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("VerifyOTPPayload", func(t *testing.T) {
		tests := []struct {
			name    string
			payload VerifyOTPPayload
			wantErr bool
		}{
			{"Valid UUID and 6-digit code", VerifyOTPPayload{UserID: "550e8400-e29b-41d4-a716-446655440000", Code: "123456"}, false},
			{"Invalid UUID", VerifyOTPPayload{UserID: "not-a-uuid", Code: "123456"}, true},
			{"Code too short", VerifyOTPPayload{UserID: "550e8400-e29b-41d4-a716-446655440000", Code: "123"}, true},
			{"Code non-numeric", VerifyOTPPayload{UserID: "550e8400-e29b-41d4-a716-446655440000", Code: "abc123"}, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := v.Validate(tt.payload)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}

func TestValidator_StandaloneMethods(t *testing.T) {
	v := NewValidator()

	t.Run("ValidateEmail", func(t *testing.T) {
		assert.NoError(t, v.ValidateEmail("hello@world.com"))
		assert.Error(t, v.ValidateEmail("invalid-email"))
	})

	t.Run("ValidatePassword", func(t *testing.T) {
		assert.NoError(t, v.ValidatePassword("longenoughpassword"))
		err := v.ValidatePassword("short")
		assert.Error(t, err)
		assert.Equal(t, "password must be at least 8 characters", err.Error())
	})

	t.Run("ValidateOTPCode", func(t *testing.T) {
		assert.NoError(t, v.ValidateOTPCode("1234", 4))
		assert.Error(t, v.ValidateOTPCode("123a", 4), "Should fail if non-numeric")
		assert.Error(t, v.ValidateOTPCode("12345", 4), "Should fail if length mismatch")
	})
}

func TestValidateSessionTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantErr bool
	}{
		{"Valid 1 hour", time.Hour, false},
		{"Valid 1 minute", time.Minute, false},
		{"Valid 24 hours", 24 * time.Hour, false},
		{"Too short (30s)", 30 * time.Second, true},
		{"Too long (25h)", 25 * time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSessionTTL(tt.ttl)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "session ttl must be between")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
