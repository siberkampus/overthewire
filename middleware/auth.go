// middleware/auth.go
package middleware

import (
    "net/http"
    "strings"
    
    "github.com/gorilla/sessions"
    "github.com/golang-jwt/jwt/v5"
)

func Auth(store *sessions.CookieStore) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Session kontrolü
            session, _ := store.Get(r, "session")
            if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
                // JWT token kontrolü
                authHeader := r.Header.Get("Authorization")
                if authHeader == "" {
                    http.Error(w, "Yetkisiz erişim", http.StatusUnauthorized)
                    return
                }

                tokenParts := strings.Split(authHeader, " ")
                if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
                    http.Error(w, "Geçersiz token formatı", http.StatusUnauthorized)
                    return
                }

                token, err := jwt.Parse(tokenParts[1], func(token *jwt.Token) (interface{}, error) {
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

                // Kullanıcı bilgilerini context'e ekle
                r.Header.Set("X-User-ID", claims["user_id"].(string))
                r.Header.Set("X-User-Username", claims["username"].(string))
            } else {
                // Session'dan kullanıcı bilgilerini al
                r.Header.Set("X-User-ID", session.Values["user_id"].(string))
                r.Header.Set("X-User-Username", session.Values["username"].(string))
            }

            next.ServeHTTP(w, r)
        })
    }
}

