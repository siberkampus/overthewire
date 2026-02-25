// models/user.go
package models

import (
	"time"
)

// models/user.go
type User struct {
	ID            int        `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	PasswordHash  string     `json:"-"` // Şifre hash'i
	FullName      string     `json:"fullname"`
	Avatar        string     `json:"avatar"`
	Bio           string     `json:"bio"`
	Location      string     `json:"country"` // Template'de kullanılıyor
	Website       string     `json:"website"` // Template'de kullanılıyor
	Points        int        `json:"points"`
	Rank          int        `json:"rank"`
	IsVIP         bool       `json:"is_vip"`
	IsActive      bool       `json:"is_active"`
	EmailVerified bool       `json:"email_verified"` // Template'de kullanılıyor
	SolvedCount   int        `json:"solved_count"`   // Template'de kullanılıyor
	CreatedAt     time.Time  `json:"created_at"`
	LastLogin     time.Time  `json:"last_login"`
	VIPExpiryDate *time.Time `json:"vip_expiry_date"`
}
