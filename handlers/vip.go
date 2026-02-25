// handlers/vip.go
package handlers

import (
    "encoding/json"
    "html/template"
    "net/http"
    "time"
    "database/sql"
    
    "ctf-platform/models"
    
    "github.com/gorilla/sessions"
)

type VIPData struct {
    Title           string
    User            *models.User
    IsAuthenticated bool
    IsVIP           bool
    VIPExpiry       *time.Time
    VIPStats        VIPStats
    Benefits        []VIPBenefit
    Testimonials    []Testimonial
}

type VIPStats struct {
    TotalVIPUsers   int
    TotalVIPMachines int
    AverageRating   float64
}

type VIPBenefit struct {
    Icon        string
    Title       string
    Description string
    Note        string
}

type Testimonial struct {
    Username string
    Avatar   string
    Text     string
    Rating   int
    Duration string
}

type PurchaseRequest struct {
    Package     string `json:"package"`
    PaymentMethod string `json:"payment_method"`
    CampaignCode string `json:"campaign_code"`
}

func GetVIPStatus(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        userID := r.Header.Get("X-User-ID")

        var isVIP bool
        var expiryDate *time.Time
        db.QueryRow(`
            SELECT is_vip, vip_expiry_date
            FROM users
            WHERE id = $1
        `, userID).Scan(&isVIP, &expiryDate)
		var daysLeft int
		if expiryDate != nil {
            // expiryDate nil değilse süreyi hesapla
            hours := time.Until(*expiryDate).Hours()
            daysLeft = int(hours / 24)
        } else {
            // expiryDate nil ise 0 ata
            daysLeft = 0
        }
        json.NewEncoder(w).Encode(map[string]interface{}{
            "is_vip":       isVIP,
            "expiry_date":  expiryDate,
            "days_remaining": daysLeft,
        })
    }
}

func PurchaseVIP(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        userID := r.Header.Get("X-User-ID")

        var req PurchaseRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Geçersiz istek", http.StatusBadRequest)
            return
        }

        // Paket fiyatları
        prices := map[string]float64{
            "monthly":  99,
            "yearly":   999,
            "lifetime": 2999,
        }

        price, ok := prices[req.Package]
        if !ok {
            http.Error(w, "Geçersiz paket", http.StatusBadRequest)
            return
        }

        // Kampanya kodu kontrolü
        if req.CampaignCode != "" {
            var discount int
            db.QueryRow(`
                SELECT discount_percent 
                FROM campaign_codes 
                WHERE code = $1 AND is_active = true 
                  AND expires_at > NOW()
            `, req.CampaignCode).Scan(&discount)

            if discount > 0 {
                price = price * (1 - float64(discount)/100)
            }
        }

        // Ödeme işlemi simülasyonu
        // Gerçek uygulamada ödeme gateway entegrasyonu olacak

        // VIP süresini hesapla
        var expiryDate time.Time
        switch req.Package {
        case "monthly":
            expiryDate = time.Now().AddDate(0, 1, 0)
        case "yearly":
            expiryDate = time.Now().AddDate(1, 0, 0)
        case "lifetime":
            expiryDate = time.Now().AddDate(100, 0, 0) // 100 yıl
        }

        // Kullanıcıyı VIP yap
        tx, err := db.Begin()
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        _, err = tx.Exec(`
            UPDATE users 
            SET is_vip = true, vip_expiry_date = $1 
            WHERE id = $2
        `, expiryDate, userID)

        if err != nil {
            tx.Rollback()
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Satın alma geçmişine ekle
        _, err = tx.Exec(`
            INSERT INTO vip_purchases (user_id, package, price, payment_method, purchased_at, expiry_date)
            VALUES ($1, $2, $3, $4, NOW(), $5)
        `, userID, req.Package, price, req.PaymentMethod, expiryDate)

        if err != nil {
            tx.Rollback()
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        tx.Commit()

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":       true,
            "message":       "VIP üyelik aktifleştirildi!",
            "expiry_date":   expiryDate,
            "package":       req.Package,
            "price":         price,
        })
    }
}

func VIPPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session")
        isAuth := false
        var user *models.User
        var isVIP bool
        var vipExpiry *time.Time

        if auth, ok := session.Values["authenticated"].(bool); ok && auth {
            isAuth = true
            userID := session.Values["user_id"].(int)
            
            user = &models.User{}
            db.QueryRow(`
                SELECT id, username, email, is_vip, vip_expiry_date, points 
                FROM users WHERE id = $1
            `, userID).Scan(&user.ID, &user.Username, &user.Email, &user.IsVIP, &user.VIPExpiryDate, &user.Points)

            isVIP = user.IsVIP
            vipExpiry = user.VIPExpiryDate
        }

        // VIP istatistikleri
        var stats VIPStats
        db.QueryRow("SELECT COUNT(*) FROM users WHERE is_vip = true").Scan(&stats.TotalVIPUsers)
        db.QueryRow("SELECT COUNT(*) FROM machines WHERE is_vip_only = true").Scan(&stats.TotalVIPMachines)
        stats.AverageRating = 4.8

        // VIP avantajları
        benefits := []VIPBenefit{
            {
                Icon:        "fa-lock-open",
                Title:       "Özel VIP Makineler",
                Description: "Sadece VIP üyelere özel 50+ zorlu makineye erişim",
                Note:        "Her ay yeni makineler ekleniyor",
            },
            {
                Icon:        "fa-trophy",
                Title:       "Çift Puan",
                Description: "Tüm çözümlerden 2 kat daha fazla puan kazanın",
                Note:        "Normalde 100 puan, VIP'ler için 200 puan",
            },
            {
                Icon:        "fa-medal",
                Title:       "Özel Rozetler",
                Description: "VIP üyelere özel 10+ rozet ve profil görünümü",
                Note:        "Profilinizde VIP rozeti görünsün",
            },
            {
                Icon:        "fa-rocket",
                Title:       "Öncelikli Destek",
                Description: "Sorularınıza öncelikli yanıt ve 7/24 destek",
                Note:        "Ortalama 1 saat içinde yanıt",
            },
            {
                Icon:        "fa-chart-line",
                Title:       "Detaylı İstatistikler",
                Description: "Gelişmiş analitik ve performans grafikleri",
                Note:        "Çözümlerinizin detaylı analizi",
            },
            {
                Icon:        "fa-users",
                Title:       "Özel Topluluk",
                Description: "VIP üyeler için özel Discord kanalı ve etkinlikler",
                Note:        "Diğer VIP üyelerle tanışın",
            },
        }

        // Yorumlar
        testimonials := []Testimonial{
            {
                Username: "@root_hunter",
                Avatar:   "https://www.gravatar.com/avatar/111...",
                Text:     "VIP makineler gerçekten zorlayıcı! Çift puan sayesinde leaderboard'da hızla yükseldim.",
                Rating:   5,
                Duration: "1 yıl",
            },
            {
                Username: "@byte_bender",
                Avatar:   "https://www.gravatar.com/avatar/333...",
                Text:     "Özel Discord kanalı harika! Diğer VIP üyelerle fikir alışverişi yapmak çok değerli.",
                Rating:   5,
                Duration: "6 ay",
            },
            {
                Username: "@payload_master",
                Avatar:   "https://www.gravatar.com/avatar/444...",
                Text:     "Öncelikli destek mükemmel çalışıyor. Sorun yaşadığımda çok hızlı çözüm alıyorum.",
                Rating:   5,
                Duration: "2 yıl",
            },
        }

        data := VIPData{
            Title:           "VIP Üyelik - CTF HACK PLATFORMU",
            User:            user,
            IsAuthenticated: isAuth,
            IsVIP:           isVIP,
            VIPExpiry:       vipExpiry,
            VIPStats:        stats,
            Benefits:        benefits,
            Testimonials:    testimonials,
        }

        tmpl := template.Must(template.ParseFiles("templates/vip.html"))
        tmpl.Execute(w, data)
    }
}