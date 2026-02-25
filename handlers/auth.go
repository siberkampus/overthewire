// handlers/auth.go
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"ctf-platform/models"
	"database/sql"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type LoginResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Token   string      `json:"token,omitempty"`
	User    models.User `json:"user,omitempty"`
}

type RegisterRequest struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Fullname   string `json:"fullname"`
	Country    string `json:"country"`
	Referral   string `json:"referral"`
	Newsletter bool   `json:"newsletter"`
}

func Login(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Kullanıcıyı veritabanında ara
		var user models.User
		err := db.QueryRow(`
            SELECT id, username, email, password_hash, is_vip, points 
            FROM users WHERE username = $1 OR email = $1
        `, req.Username).Scan(
			&user.ID, &user.Username, &user.Email,
			&user.PasswordHash, &user.IsVIP, &user.Points,
		)

		if err != nil {
			json.NewEncoder(w).Encode(LoginResponse{
				Success: false,
				Message: "Kullanıcı bulunamadı",
			})
			return
		}

		// Şifre kontrolü
		err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
		if err != nil {
			json.NewEncoder(w).Encode(LoginResponse{
				Success: false,
				Message: "Hatalı şifre",
			})
			return
		}

		// JWT token oluştur
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":  user.ID,
			"username": user.Username,
			"is_vip":   user.IsVIP,
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte("jwt-secret-key"))
		if err != nil {
			http.Error(w, "Token oluşturulamadı", http.StatusInternalServerError)
			return
		}

		// Session oluştur
		session, _ := store.Get(r, "session")
		session.Values["authenticated"] = true
		session.Values["user_id"] = user.ID
		session.Values["username"] = user.Username
		session.Values["is_vip"] = user.IsVIP

		if req.Remember {
			session.Options.MaxAge = 86400 * 30 // 30 gün
		} else {
			session.Options.MaxAge = 86400 // 1 gün
		}

		session.Save(r, w)

		// Son giriş zamanını güncelle
		db.Exec("UPDATE users SET last_login = NOW() WHERE id = $1", user.ID)

		json.NewEncoder(w).Encode(LoginResponse{
			Success: true,
			Token:   tokenString,
			User:    user,
		})
	}
}

func Register(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Validasyonlar
		if len(req.Username) < 3 || len(req.Username) > 20 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Kullanıcı adı 3-20 karakter arasında olmalı",
			})
			return
		}

		if len(req.Password) < 8 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Şifre en az 8 karakter olmalı",
			})
			return
		}

		// Email validasyonu
		if !strings.Contains(req.Email, "@") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Geçerli bir email adresi girin",
			})
			return
		}

		// Şifreyi hashle
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Şifre hashlenemedi", http.StatusInternalServerError)
			return
		}

		// Kullanıcıyı veritabanına ekle (tüm alanlarla)
		var userID int
		err = db.QueryRow(`
            INSERT INTO users (username, email, password_hash, fullname, country, referral_code, newsletter, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            RETURNING id
        `,
			req.Username,
			req.Email,
			string(hashedPassword),
			req.Fullname,
			req.Country,
			req.Referral,
			req.Newsletter,
		).Scan(&userID)

		if err != nil {
			// Duplicate key hatası kontrolü
			if strings.Contains(err.Error(), "duplicate key") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "Bu kullanıcı adı veya email zaten kullanılıyor",
				})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Kayıt sırasında bir hata oluştu",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Kayıt başarılı",
			"user_id": userID,
			"user": map[string]interface{}{
				"id":       userID,
				"username": req.Username,
				"email":    req.Email,
				"fullname": req.Fullname,
			},
		})
	}
}
func Logout(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		session.Values["authenticated"] = false
		session.Options.MaxAge = -1
		session.Save(r, w)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Çıkış yapıldı",
		})
	}
}

func RefreshToken(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Token'ı doğrula
		token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
			return []byte("jwt-secret-key"), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Geçersiz token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Geçersiz token claims", http.StatusUnauthorized)
			return
		}

		// Yeni token oluştur
		newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":  claims["user_id"],
			"username": claims["username"],
			"is_vip":   claims["is_vip"],
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
		})

		tokenString, err := newToken.SignedString([]byte("jwt-secret-key"))
		if err != nil {
			http.Error(w, "Token oluşturulamadı", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"token":   tokenString,
		})
	}
}
