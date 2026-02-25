// handlers/settings.go
package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"ctf-platform/models"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type SettingsData struct {
	Title           string
	User            *models.User
	IsAuthenticated bool
	Settings        UserSettings
	Sessions        []UserSession
}

type UserSettings struct {
	EmailNotifications   bool   `json:"email_notifications"`
	BrowserNotifications bool   `json:"browser_notifications"`
	SoundEnabled         bool   `json:"sound_enabled"`
	ProfilePublic        bool   `json:"profile_public"`
	ShowActivity         bool   `json:"show_activity"`
	ShowOnlineStatus     bool   `json:"show_online_status"`
	Theme                string `json:"theme"`
	FontSize             string `json:"font_size"`
	Language             string `json:"language"`
}

type UserSession struct {
	ID         int    `json:"id"`
	Device     string `json:"device"`
	IP         string `json:"ip"`
	Location   string `json:"location"`
	LastActive string `json:"last_active"`
	IsCurrent  bool   `json:"is_current"`
}

type UpdateSettingsRequest struct {
	Settings UserSettings `json:"settings"`
}

type UpdateSecurityRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	Enable2FA       bool   `json:"enable_2fa"`
}

type TerminateSessionRequest struct {
	SessionID int `json:"session_id"`
}

func GetSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")

		var settings UserSettings
		err := db.QueryRow(`
            SELECT email_notifications, browser_notifications, sound_enabled,
                   profile_public, show_activity, show_online_status,
                   theme, font_size, language
            FROM user_settings
            WHERE user_id = $1
        `, userID).Scan(
			&settings.EmailNotifications, &settings.BrowserNotifications, &settings.SoundEnabled,
			&settings.ProfilePublic, &settings.ShowActivity, &settings.ShowOnlineStatus,
			&settings.Theme, &settings.FontSize, &settings.Language,
		)

		if err != nil {
			// Varsayılan ayarlar
			settings = UserSettings{
				EmailNotifications:   true,
				BrowserNotifications: true,
				SoundEnabled:         false,
				ProfilePublic:        true,
				ShowActivity:         true,
				ShowOnlineStatus:     true,
				Theme:                "dark",
				FontSize:             "medium",
				Language:             "tr",
			}
		}

		json.NewEncoder(w).Encode(settings)
	}
}

func UpdateSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")

		var req UpdateSettingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Ayarları güncelle
		_, err := db.Exec(`
            INSERT INTO user_settings (
                user_id, email_notifications, browser_notifications, sound_enabled,
                profile_public, show_activity, show_online_status,
                theme, font_size, language, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                email_notifications = $2,
                browser_notifications = $3,
                sound_enabled = $4,
                profile_public = $5,
                show_activity = $6,
                show_online_status = $7,
                theme = $8,
                font_size = $9,
                language = $10,
                updated_at = NOW()
        `, userID,
			req.Settings.EmailNotifications,
			req.Settings.BrowserNotifications,
			req.Settings.SoundEnabled,
			req.Settings.ProfilePublic,
			req.Settings.ShowActivity,
			req.Settings.ShowOnlineStatus,
			req.Settings.Theme,
			req.Settings.FontSize,
			req.Settings.Language,
		)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Ayarlar güncellendi",
		})
	}
}

func UpdateSecurity(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")

		var req UpdateSecurityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Şifre değiştirme
		if req.NewPassword != "" {
			// Mevcut şifreyi kontrol et
			var passwordHash string
			db.QueryRow("SELECT password_hash FROM users WHERE id = $1", userID).Scan(&passwordHash)

			err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.CurrentPassword))
			if err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "Mevcut şifre hatalı",
				})
				return
			}

			// Yeni şifreyi hashle
			newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Şifreyi güncelle
			_, err = db.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", newHash, userID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// 2FA ayarları
		if req.Enable2FA {
			// 2FA kurulumu (gerçek uygulamada QR kod vs)
			_, err := db.Exec("UPDATE users SET two_factor_enabled = true WHERE id = $1", userID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Güvenlik ayarları güncellendi",
		})
	}
}

func GetSessions(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")
		currentSessionID := r.Header.Get("X-Session-ID")

		rows, err := db.Query(`
            SELECT id, device, ip_address, location, last_activity
            FROM user_sessions
            WHERE user_id = $1 AND is_active = true
            ORDER BY last_activity DESC
        `, userID)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var sessions []UserSession
		for rows.Next() {
			var s UserSession
			rows.Scan(&s.ID, &s.Device, &s.IP, &s.Location, &s.LastActive)
			s.IsCurrent = strconv.Itoa(s.ID) == currentSessionID
			sessions = append(sessions, s)
		}

		json.NewEncoder(w).Encode(sessions)
	}
}

func TerminateSession(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		sessionID := vars["id"]
		userID := r.Header.Get("X-User-ID")
		currentSessionID := r.Header.Get("X-Session-ID")

		// Kendi oturumunu sonlandırmaya çalışıyorsa engelle
		if sessionID == currentSessionID {
			http.Error(w, "Mevcut oturum sonlandırılamaz", http.StatusBadRequest)
			return
		}

		// Oturumu sonlandır
		_, err := db.Exec(`
            UPDATE user_sessions 
            SET is_active = false, terminated_at = NOW() 
            WHERE id = $1 AND user_id = $2
        `, sessionID, userID)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Oturum sonlandırıldı",
		})
	}
}

func TerminateAllSessions(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")
		currentSessionID := r.Header.Get("X-Session-ID")

		// Diğer tüm oturumları sonlandır
		_, err := db.Exec(`
            UPDATE user_sessions 
            SET is_active = false, terminated_at = NOW() 
            WHERE user_id = $1 AND id != $2
        `, userID, currentSessionID)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Diğer tüm oturumlar sonlandırıldı",
		})
	}
}

func SettingsPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		isAuth := false
		var user *models.User
		var settings UserSettings
		var sessions []UserSession
		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			isAuth = true
			userID := session.Values["user_id"].(int)

			user = &models.User{}
			db.QueryRow(`
                SELECT id, username, email, avatar, is_vip, points 
                FROM users WHERE id = $1
            `, userID).Scan(&user.ID, &user.Username, &user.Email, &user.Avatar, &user.IsVIP, &user.Points)

			// Kullanıcı ayarlarını getir
			err := db.QueryRow(`
                SELECT email_notifications, browser_notifications, sound_enabled,
                       profile_public, show_activity, show_online_status,
                       theme, font_size, language
                FROM user_settings
                WHERE user_id = $1
            `, userID).Scan(
				&settings.EmailNotifications, &settings.BrowserNotifications, &settings.SoundEnabled,
				&settings.ProfilePublic, &settings.ShowActivity, &settings.ShowOnlineStatus,
				&settings.Theme, &settings.FontSize, &settings.Language,
			)

			if err != nil {
				// Varsayılan ayarlar
				settings = UserSettings{
					EmailNotifications:   true,
					BrowserNotifications: true,
					SoundEnabled:         false,
					ProfilePublic:        true,
					ShowActivity:         true,
					ShowOnlineStatus:     true,
					Theme:                "dark",
					FontSize:             "medium",
					Language:             "tr",
				}
			}

			// Aktif oturumları getir
			rows, err := db.Query(`
                SELECT id, device, ip_address, location, last_activity
                FROM user_sessions
                WHERE user_id = $1 AND is_active = true
                ORDER BY last_activity DESC
            `, userID)

			
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var s UserSession
					rows.Scan(&s.ID, &s.Device, &s.IP, &s.Location, &s.LastActive)
					sessions = append(sessions, s)
				}
			}
		}

		data := SettingsData{
			Title:           "Ayarlar - CTF HACK PLATFORMU",
			User:            user,
			IsAuthenticated: isAuth,
			Settings:        settings,
			Sessions:        sessions,
		}

		tmpl := template.Must(template.ParseFiles("templates/settings.html"))
		tmpl.Execute(w, data)
	}
}

func UploadAvatar(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")

		// Dosya yükleme işlemi
		r.ParseMultipartForm(10 << 20) // 10 MB limit

		file, handler, err := r.FormFile("avatar")
		if err != nil {
			http.Error(w, "Dosya yüklenemedi", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Dosya tipi kontrolü
		if !strings.HasPrefix(handler.Header.Get("Content-Type"), "image/") {
			http.Error(w, "Sadece resim dosyaları yüklenebilir", http.StatusBadRequest)
			return
		}

		// Dosya boyutu kontrolü
		if handler.Size > 2*1024*1024 { // 2MB
			http.Error(w, "Dosya boyutu 2MB'dan büyük olamaz", http.StatusBadRequest)
			return
		}

		// Dosyayı kaydet
		filename := fmt.Sprintf("avatars/%s_%s", userID, handler.Filename)
		// Gerçek uygulamada dosyayı kaydetme işlemi

		// Avatar URL'ini veritabanına kaydet
		avatarURL := "/static/" + filename
		_, err = db.Exec("UPDATE users SET avatar = $1 WHERE id = $2", avatarURL, userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"avatar":  avatarURL,
			"message": "Avatar başarıyla güncellendi",
		})
	}
}
