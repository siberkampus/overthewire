package models

import "time"

type SystemSettings struct {
	SiteName          string   `json:"site_name"`
	SiteDescription   string   `json:"site_description"`
	SiteKeywords      string   `json:"site_keywords"`
	MaintenanceMode   bool     `json:"maintenance_mode"`
	RegistrationOpen  bool     `json:"registration_open"`
	DefaultUserPoints int      `json:"default_user_points"`
	SessionTimeout    int      `json:"session_timeout"` // dakika
	MaxUploadSize     int64    `json:"max_upload_size"` // MB
	AllowedFileTypes  []string `json:"allowed_file_types"`
	EmailSettings     EmailSettings
	SecuritySettings  SecuritySettings
	CTFSettings       CTFSettings
}

type EmailSettings struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	FromEmail    string `json:"from_email"`
}

type SecuritySettings struct {
	TwoFactorAuth   bool     `json:"two_factor_auth"`
	PasswordMinLen  int      `json:"password_min_len"`
	PasswordComplex bool     `json:"password_complex"`
	LoginAttempts   int      `json:"login_attempts"`
	BlockDuration   int      `json:"block_duration"` // dakika
	AllowedIPs      []string `json:"allowed_ips"`
	BlockedIPs      []string `json:"blocked_ips"`
}

type CTFSettings struct {
	EnableCTF        bool `json:"enable_ctf"`
	CTFStartTime     time.Time
	CTFEndTime       time.Time
	MaxTeamSize      int    `json:"max_team_size"`
	EnableScoreboard bool   `json:"enable_scoreboard"`
	FlagFormat       string `json:"flag_format"`
}
