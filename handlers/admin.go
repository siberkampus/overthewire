// handlers/admin.go
package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ctf-platform/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type AdminLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func calculatePercentage(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

// ==================== ADMIN HTML SAYFALARI ====================

// AdminLoginPage - Admin giriş sayfası
func AdminLoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Admin Giriş - CTF Platform",
	}

	tmpl := template.Must(template.ParseFiles("templates/admin/admin_login.html"))
	tmpl.Execute(w, data)
}

// AdminDashboardPage - Admin dashboard sayfası
func AdminDashboard(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var stats models.AdminStats

		// Toplam kullanıcı
		db.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = true").Scan(&stats.TotalUsers)

		// Bugün kaydolanlar
		db.QueryRow(`
            SELECT COUNT(*) FROM users 
            WHERE DATE(created_at) = CURRENT_DATE
        `).Scan(&stats.NewUsersToday)

		// Aktif kullanıcılar (son 24 saat)
		db.QueryRow(`
            SELECT COUNT(*) FROM users 
            WHERE last_login > NOW() - INTERVAL '24 hours'
        `).Scan(&stats.ActiveUsers)

		// Toplam makine
		db.QueryRow("SELECT COUNT(*) FROM machines WHERE is_active = true").Scan(&stats.TotalMachines)

		// Toplam çözüm
		db.QueryRow("SELECT COUNT(*) FROM submissions").Scan(&stats.TotalSubmissions)

		// Bugünkü çözümler
		db.QueryRow(`
            SELECT COUNT(*) FROM submissions 
            WHERE DATE(created_at) = CURRENT_DATE
        `).Scan(&stats.SubmissionsToday)

		// Toplam VIP kullanıcı
		db.QueryRow("SELECT COUNT(*) FROM users WHERE is_vip = true").Scan(&stats.TotalVIPUsers)

		// VIP geliri
		db.QueryRow(`
            SELECT COALESCE(SUM(price), 0) FROM vip_purchases 
            WHERE DATE(purchased_at) = CURRENT_DATE
        `).Scan(&stats.VIPRevenue)

		// Ortalama puan
		db.QueryRow("SELECT COALESCE(AVG(points), 0) FROM users").Scan(&stats.AveragePoints)

		// En yüksek puan
		db.QueryRow("SELECT COALESCE(MAX(points), 0) FROM users").Scan(&stats.TopUserPoints)

		// Başarı oranı
		var total, success int
		db.QueryRow("SELECT COUNT(*) FROM submissions").Scan(&total)
		db.QueryRow("SELECT COUNT(*) FROM submissions WHERE status = 'accepted'").Scan(&success)
		if total > 0 {
			stats.SuccessRate = float64(success) / float64(total) * 100
		}

		// Son kullanıcılar
		rows, err := db.Query(`
            SELECT id, username, email, points, is_vip, created_at 
            FROM users 
            WHERE is_active = true 
            ORDER BY created_at DESC 
            LIMIT 10
        `)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var recentUsers []models.User
		for rows.Next() {
			var u models.User
			rows.Scan(&u.ID, &u.Username, &u.Email, &u.Points, &u.IsVIP, &u.CreatedAt)
			recentUsers = append(recentUsers, u)
		}

		// Son çözümler
		rows, err = db.Query(`
            SELECT s.id, u.username, m.name, q.title, s.status, s.created_at
            FROM submissions s
            JOIN users u ON s.user_id = u.id
            JOIN machines m ON s.machine_id = m.id
            JOIN machine_questions q ON s.question_id = q.id
            ORDER BY s.created_at DESC
            LIMIT 10
        `)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var recentSubmissions []models.Submission
		for rows.Next() {
			var s models.Submission
			rows.Scan(&s.ID, &s.Username, &s.MachineName, &s.QuestionTitle, &s.Status, &s.SubmittedAt)
			recentSubmissions = append(recentSubmissions, s)
		}

		// Popüler makineler
		rows, err = db.Query(`
            SELECT m.id, m.name, m.difficulty, 
                   COUNT(s.id) as submissions,
                   ROUND(AVG(CASE WHEN s.status = 'accepted' THEN 100 ELSE 0 END)) as success_rate
            FROM machines m
            LEFT JOIN submissions s ON m.id = s.machine_id
            WHERE m.is_active = true
            GROUP BY m.id
            ORDER BY submissions DESC
            LIMIT 5
        `)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var popularMachines []models.PopularMachine
		for rows.Next() {
			var pm models.PopularMachine
			rows.Scan(&pm.ID, &pm.Name, &pm.Difficulty, &pm.Submissions, &pm.SuccessRate)
			popularMachines = append(popularMachines, pm)
		}

		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		var admin models.Admin
		admin.Username = username
		admin.Role = role
		admin.Avatar = "/static/images/avatar.png" // Varsayılan avatar

		data := models.AdminDashboardData{
			Title:             "Admin Dashboard - CTF Platform",
			Stats:             stats,
			Active:            "dashboard",
			RecentUsers:       recentUsers,
			RecentSubmissions: recentSubmissions,
			PopularMachines:   popularMachines,
			CurrentDate:       time.Now().Format("02 January 2006 - Monday"),
			ActivePercentage:  calculatePercentage(stats.ActiveUsers, stats.TotalUsers),
			Admin:             admin,
		}

		// Template fonksiyonlarını tanımla
		funcMap := template.FuncMap{
			"now": func() time.Time {
				return time.Now()
			},
			"percentage": func(part, total int) float64 {
				if total == 0 {
					return 0
				}
				return float64(part) / float64(total) * 100
			},
			"subtract": func(a, b int) int {
				return a - b
			},
			"add": func(a, b int) int {
				return a + b
			},
			"multiply": func(a, b int) int {
				return a * b
			},
			"divide": func(a, b int) float64 {
				if b == 0 {
					return 0
				}
				return float64(a) / float64(b)
			},
		}

		// Template'i parse ederken funcMap'i kullan
		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/dashboard.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template execute hatası: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// AdminUsersPage - Kullanıcı listesi sayfası
func AdminUsersPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Filtre parametrelerini al
		status := r.URL.Query().Get("status")
		vip := r.URL.Query().Get("vip")
		sort := r.URL.Query().Get("sort")
		search := r.URL.Query().Get("search")
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))

		if page < 1 {
			page = 1
		}
		limit := 20 // Sayfa başına gösterilecek kullanıcı sayısı

		// İstatistikleri getir
		var stats struct {
			TotalUsers  int
			ActiveUsers int
			VIPUsers    int
			NewToday    int
		}

		db.QueryRow("SELECT COUNT(*) FROM users").Scan(&stats.TotalUsers)
		db.QueryRow("SELECT COUNT(*) FROM users WHERE last_login > NOW() - INTERVAL '24 hours'").Scan(&stats.ActiveUsers)
		db.QueryRow("SELECT COUNT(*) FROM users WHERE is_vip = true").Scan(&stats.VIPUsers)
		db.QueryRow("SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURRENT_DATE").Scan(&stats.NewToday)

		// Kullanıcı sorgusu
		query := `
			SELECT id, username, email, fullname, avatar, points, is_vip, is_active, created_at, last_login
			FROM users
			WHERE 1=1
		`
		var args []interface{}
		argCount := 1

		// Filtreleri uygula
		if status == "active" {
			query += ` AND is_active = true`
		} else if status == "inactive" {
			query += ` AND is_active = false`
		}

		if vip == "vip" {
			query += ` AND is_vip = true`
		} else if vip == "normal" {
			query += ` AND is_vip = false`
		}

		if search != "" {
			query += ` AND (username ILIKE $` + strconv.Itoa(argCount) +
				` OR email ILIKE $` + strconv.Itoa(argCount) +
				` OR fullname ILIKE $` + strconv.Itoa(argCount) + `)`
			args = append(args, "%"+search+"%")
			argCount++
		}

		// Sıralama
		switch sort {
		case "date_asc":
			query += ` ORDER BY created_at ASC`
		case "points_desc":
			query += ` ORDER BY points DESC`
		case "points_asc":
			query += ` ORDER BY points ASC`
		case "name_asc":
			query += ` ORDER BY username ASC`
		case "name_desc":
			query += ` ORDER BY username DESC`
		default: // date_desc
			query += ` ORDER BY created_at DESC`
		}

		// Toplam kullanıcı sayısını hesapla (filtreler uygulanmış)
		var totalUsers int
		countQuery := "SELECT COUNT(*) FROM (" + query + ") AS count"
		err := db.QueryRow(countQuery, args...).Scan(&totalUsers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Sayfalama ekle
		query += ` LIMIT $` + strconv.Itoa(argCount) + ` OFFSET $` + strconv.Itoa(argCount+1)
		args = append(args, limit, (page-1)*limit)

		// Kullanıcıları getir
		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []map[string]interface{}
		for rows.Next() {
			var u struct {
				ID        int
				Username  string
				Email     string
				FullName  sql.NullString
				Avatar    sql.NullString
				Points    int
				IsVIP     bool
				IsActive  bool
				CreatedAt time.Time
				LastLogin sql.NullTime
			}
			err := rows.Scan(
				&u.ID, &u.Username, &u.Email, &u.FullName, &u.Avatar,
				&u.Points, &u.IsVIP, &u.IsActive, &u.CreatedAt, &u.LastLogin,
			)
			if err != nil {
				continue
			}

			// Avatar yoksa varsayılan kullan
			avatar := "/static/images/avatar.png"
			if u.Avatar.Valid {
				avatar = u.Avatar.String
			}

			users = append(users, map[string]interface{}{
				"ID":        u.ID,
				"Username":  u.Username,
				"Email":     u.Email,
				"FullName":  u.FullName.String,
				"Avatar":    avatar,
				"Points":    u.Points,
				"IsVIP":     u.IsVIP,
				"IsActive":  u.IsActive,
				"CreatedAt": u.CreatedAt,
				"LastLogin": u.LastLogin.Time,
			})
		}

		// Sayfalama hesapla
		totalPages := (totalUsers + limit - 1) / limit

		// Sayfa numaralarını oluştur
		var pages []int
		for i := 1; i <= totalPages; i++ {
			if i == 1 || i == totalPages || (i >= page-2 && i <= page+2) {
				pages = append(pages, i)
			}
		}

		pagination := struct {
			CurrentPage int
			TotalPages  int
			TotalItems  int
			HasPrev     bool
			HasNext     bool
			PrevPage    int
			NextPage    int
			Start       int
			End         int
			Pages       []int
		}{
			CurrentPage: page,
			TotalPages:  totalPages,
			TotalItems:  totalUsers,
			HasPrev:     page > 1,
			HasNext:     page < totalPages,
			PrevPage:    page - 1,
			NextPage:    page + 1,
			Start:       (page-1)*limit + 1,
			End:         min(page*limit, totalUsers),
			Pages:       pages,
		}

		// Filtre değerleri
		filters := struct {
			Status string
			VIP    string
			Sort   string
			Search string
		}{
			Status: status,
			VIP:    vip,
			Sort:   sort,
			Search: search,
		}

		// Admin bilgileri
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		admin := models.Admin{
			Username: username,
			Role:     role,
			Avatar:   "/static/images/avatar.png",
		}

		// Template verisi
		data := struct {
			Title      string
			Active     string
			Stats      interface{}
			Filters    interface{}
			Users      []map[string]interface{}
			Pagination interface{}
			Admin      models.Admin
		}{
			Title:      "Kullanıcı Yönetimi - Admin Panel",
			Active:     "users",
			Stats:      stats,
			Filters:    filters,
			Users:      users,
			Pagination: pagination,
			Admin:      admin,
		}

		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/users.html",
		)
		if err != nil {
			http.Error(w, "Template yüklenemedi: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template çalıştırılamadı: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// AdminAddUserForm - Yeni kullanıcı ekleme formu
func AdminAddUserForm(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		var admin models.Admin
		admin.Username = username
		admin.Role = role
		admin.Avatar = "/static/images/avatar.png"

		// Boş kullanıcı oluştur (tüm alanlar varsayılan)
		emptyUser := models.User{
			IsActive:      true,
			IsVIP:         false,
			EmailVerified: false,
			Points:        0,
			SolvedCount:   0,
		}

		data := struct {
			Title  string
			Active string
			User   models.User
			Admin  models.Admin
		}{
			Title:  "Yeni Kullanıcı Ekle - Admin Panel",
			Active: "users",
			User:   emptyUser,
			Admin:  admin,
		}

		// Template fonksiyonlarını ekle (eq için)
		funcMap := template.FuncMap{
			"eq": func(a, b interface{}) bool {
				return a == b
			},
		}

		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/user_form.html",
		)
		if err != nil {
			http.Error(w, "Template yüklenemedi: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template çalıştırılamadı: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// AdminEditUserForm - Kullanıcı düzenleme formu
func AdminEditUserForm(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		var user models.User
		err := db.QueryRow(`
            SELECT id, username, email, fullname, bio, location, website,
                   points, is_vip, is_active, created_at, last_login
            FROM users WHERE id = $1
        `, userID).Scan(
			&user.ID, &user.Username, &user.Email, &user.FullName,
			&user.Bio, &user.Location, &user.Website, &user.Points,
			&user.IsVIP, &user.IsActive, &user.CreatedAt, &user.LastLogin,
		)

		if err != nil {
			http.Error(w, "Kullanıcı bulunamadı", http.StatusNotFound)
			return
		}

		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		var admin models.Admin
		admin.Username = username
		admin.Role = role

		data := struct {
			Title  string
			Active string
			User   models.User
			Admin  models.Admin
		}{
			Title:  "Kullanıcı Düzenle - Admin Panel",
			Active: "users",
			User:   user,
			Admin:  admin,
		}

		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/user_form.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, data)
	}
}

// AdminMachinesPage - Makine listesi sayfası
func AdminMachinesPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Sayfalama parametreleri
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 20
		}

		// Filtre parametreleri
		difficulty := r.URL.Query().Get("difficulty")
		status := r.URL.Query().Get("status")
		vip := r.URL.Query().Get("vip")
		search := r.URL.Query().Get("search")

		// Makineleri getir (sayfalı)
		query := `
            SELECT m.id, m.name, m.description, m.difficulty, m.points_reward,
                   m.is_vip_only, m.is_active, m.created_at,
                   COALESCE(u.username, 'System') as creator,
                   COUNT(DISTINCT mq.id) as question_count,
                   COUNT(DISTINCT s.id) as submission_count
            FROM machines m
            LEFT JOIN users u ON m.creator_id = u.id
            LEFT JOIN machine_questions mq ON m.id = mq.machine_id
            LEFT JOIN submissions s ON m.id = s.machine_id
            WHERE 1=1
        `
		var args []interface{}
		argCount := 1

		if difficulty != "" && difficulty != "all" {
			query += ` AND m.difficulty = $` + strconv.Itoa(argCount)
			args = append(args, difficulty)
			argCount++
		}

		if status != "" && status != "all" {
			if status == "active" {
				query += ` AND m.is_active = true`
			} else if status == "inactive" {
				query += ` AND m.is_active = false`
			}
		}

		if vip != "" && vip != "all" {
			if vip == "vip" {
				query += ` AND m.is_vip_only = true`
			} else if vip == "free" {
				query += ` AND m.is_vip_only = false`
			}
		}

		if search != "" {
			query += ` AND m.name ILIKE $` + strconv.Itoa(argCount)
			args = append(args, "%"+search+"%")
			argCount++
		}

		query += ` GROUP BY m.id, u.username`

		// Toplam sayı
		var total int
		countQuery := "SELECT COUNT(*) FROM (" + query + ") AS count"
		err := db.QueryRow(countQuery, args...).Scan(&total)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Sayfalama
		query += ` ORDER BY m.created_at DESC 
                   LIMIT $` + strconv.Itoa(argCount) + ` 
                   OFFSET $` + strconv.Itoa(argCount+1)
		args = append(args, limit, (page-1)*limit)

		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Machines slice'ını doldur
		var machines []map[string]interface{}
		for rows.Next() {
			var m struct {
				ID              int
				Name            string
				Description     string
				Difficulty      string
				PointsReward    int
				IsVIPOnly       bool
				IsActive        bool
				CreatedAt       time.Time
				Creator         string
				QuestionCount   int
				SubmissionCount int
			}
			err := rows.Scan(
				&m.ID, &m.Name, &m.Description, &m.Difficulty, &m.PointsReward,
				&m.IsVIPOnly, &m.IsActive, &m.CreatedAt,
				&m.Creator, &m.QuestionCount, &m.SubmissionCount,
			)
			if err != nil {
				continue
			}

			machines = append(machines, map[string]interface{}{
				"ID":             m.ID,
				"Name":           m.Name,
				"Description":    m.Description,
				"Difficulty":     m.Difficulty,
				"PointsReward":   m.PointsReward,
				"IsVIPOnly":      m.IsVIPOnly,
				"IsActive":       m.IsActive,
				"CreatedAt":      m.CreatedAt,
				"Creator":        m.Creator,
				"TotalQuestions": m.QuestionCount,
				"SolverCount":    m.SubmissionCount,
				"ImageURL":       "/static/images/machines/default.png", // Varsayılan görsel
			})
		}

		// İstatistikleri getir
		var stats struct {
			TotalMachines  int
			ActiveMachines int
			EasyCount      int
			MediumCount    int
			HardCount      int
			ExpertCount    int
		}

		db.QueryRow("SELECT COUNT(*) FROM machines").Scan(&stats.TotalMachines)
		db.QueryRow("SELECT COUNT(*) FROM machines WHERE is_active = true").Scan(&stats.ActiveMachines)
		db.QueryRow("SELECT COUNT(*) FROM machines WHERE difficulty = 'easy'").Scan(&stats.EasyCount)
		db.QueryRow("SELECT COUNT(*) FROM machines WHERE difficulty = 'medium'").Scan(&stats.MediumCount)
		db.QueryRow("SELECT COUNT(*) FROM machines WHERE difficulty = 'hard'").Scan(&stats.HardCount)
		db.QueryRow("SELECT COUNT(*) FROM machines WHERE difficulty = 'expert'").Scan(&stats.ExpertCount)

		// Sayfalama hesapla
		totalPages := (total + limit - 1) / limit

		// Sayfa numaralarını oluştur
		var pages []int
		for i := 1; i <= totalPages; i++ {
			if i == 1 || i == totalPages || (i >= page-2 && i <= page+2) {
				pages = append(pages, i)
			}
		}

		pagination := struct {
			CurrentPage int
			TotalPages  int
			HasPrev     bool
			HasNext     bool
			PrevPage    int
			NextPage    int
			Pages       []int
		}{
			CurrentPage: page,
			TotalPages:  totalPages,
			HasPrev:     page > 1,
			HasNext:     page < totalPages,
			PrevPage:    page - 1,
			NextPage:    page + 1,
			Pages:       pages,
		}

		// Admin bilgileri
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		admin := models.Admin{
			Username: username,
			Role:     role,
			Avatar:   "/static/images/avatar.png",
		}

		// Template verisi
		data := struct {
			Title      string
			Active     string
			Stats      interface{}
			Machines   []map[string]interface{}
			Pagination interface{}
			Admin      models.Admin
		}{
			Title:      "Makine Yönetimi - Admin Panel",
			Active:     "machines",
			Stats:      stats,
			Machines:   machines,
			Pagination: pagination,
			Admin:      admin,
		}

		// Template fonksiyonları
		funcMap := template.FuncMap{
			"title": strings.Title,
		}

		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/machines.html",
		)
		if err != nil {
			http.Error(w, "Template yüklenemedi: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template çalıştırılamadı: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// AdminAddMachineForm - Yeni makine ekleme formu
func AdminAddMachineForm(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		difficulties := []string{"easy", "medium", "hard", "expert"}

		// Session'dan admin bilgilerini al
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		// Admin struct'ını oluştur
		admin := models.Admin{
			Username: username,
			Role:     role,
			Avatar:   "/static/images/avatar.png",
		}

		// Template fonksiyonlarını tanımla
		funcMap := template.FuncMap{
			"add": func(a, b int) int {
				return a + b
			},
		}

		data := struct {
			Title        string
			Active       string
			Machine      models.Machine
			Difficulties []string
			Admin        models.Admin // Admin alanını ekle
		}{
			Title:  "Yeni Makine Ekle - Admin Panel",
			Active: "machines",
			Machine: models.Machine{
				IsActive:  true,
				IsVIPOnly: false,
			},
			Difficulties: difficulties,
			Admin:        admin, // Admin bilgisini ata
		}

		// Template'i parse et
		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/machine_form.html",
		)
		if err != nil {
			http.Error(w, "Template yüklenemedi: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template çalıştırılamadı: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// AdminEditMachineForm - Makine düzenleme formu
func AdminEditMachineForm(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		var machine models.Machine
		err := db.QueryRow(`
            SELECT id, name, description, difficulty, points_reward, 
                   is_vip_only, docker_image, creator, is_active
            FROM machines WHERE id = $1
        `, id).Scan(
			&machine.ID, &machine.Name, &machine.Description, &machine.Difficulty,
			&machine.PointsReward, &machine.IsVIPOnly, &machine.DockerImage,
			&machine.Creator, &machine.IsActive,
		)

		if err != nil {
			http.Error(w, "Makine bulunamadı", http.StatusNotFound)
			return
		}

		// Soruları getir
		rows, err := db.Query(`
            SELECT id, title, description, points_reward, hint, hint_cost, is_active
            FROM machine_questions
            WHERE machine_id = $1
            ORDER BY id
        `, id)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var q models.Question
				rows.Scan(&q.ID, &q.Title, &q.Description, &q.PointsReward,
					&q.Hint, &q.HintCost, &q.IsActive)
				machine.Questions = append(machine.Questions, q)
			}
		}

		difficulties := []string{"easy", "medium", "hard", "expert"}

		data := struct {
			Title        string
			Active       string
			Machine      models.Machine
			Difficulties []string
		}{
			Title:        "Makine Düzenle - Admin Panel",
			Active:       "machines",
			Machine:      machine,
			Difficulties: difficulties,
		}

		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/machine_form.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, data)
	}
}

// AdminQuestionsPage - Soru listesi sayfası
func AdminQuestionsPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Makineleri getir (filtre için)
		rows, err := db.Query("SELECT id, name FROM machines ORDER BY name")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var machines []models.Machine
		for rows.Next() {
			var m models.Machine
			rows.Scan(&m.ID, &m.Name)
			machines = append(machines, m)
		}
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		var admin models.Admin
		admin.Username = username
		admin.Role = role
		admin.Avatar = "/static/images/avatar.png" // Varsayılan avatar

		data := struct {
			Title    string
			Active   string
			Machines []models.Machine
			Admin    models.Admin
		}{
			Title:    "Soru Yönetimi - Admin Panel",
			Active:   "questions",
			Machines: machines,
			Admin:    admin,
		}

		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/questions.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, data)
	}
}

// AdminVIPPage - VIP yönetim sayfası
func AdminVIPPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		// VIP istatistiklerini getir
		var stats struct {
			TotalVIP       int
			ActiveVIP      int
			TotalRevenue   float64
			MonthlyRevenue float64
			ExpiringSoon   int
		}

		// Toplam VIP kullanıcı
		db.QueryRow("SELECT COUNT(*) FROM users WHERE is_vip = true").Scan(&stats.TotalVIP)

		// Aktif VIP (süresi dolmamış)
		db.QueryRow("SELECT COUNT(*) FROM users WHERE is_vip = true AND (vip_expiry_date > NOW() OR vip_expiry_date IS NULL)").Scan(&stats.ActiveVIP)

		// Toplam gelir (vip_purchases tablosundan)
		db.QueryRow("SELECT COALESCE(SUM(price), 0) FROM vip_purchases").Scan(&stats.TotalRevenue)

		// Aylık gelir
		db.QueryRow("SELECT COALESCE(SUM(price), 0) FROM vip_purchases WHERE purchased_at > NOW() - INTERVAL '30 days'").Scan(&stats.MonthlyRevenue)

		// Yakında bitecek VIP'ler (7 gün içinde)
		db.QueryRow(`
			SELECT COUNT(*) FROM users 
			WHERE is_vip = true 
			AND vip_expiry_date BETWEEN NOW() AND NOW() + INTERVAL '7 days'
		`).Scan(&stats.ExpiringSoon)

		// VIP paketleri (vip_purchases'tan benzersiz paketleri al)
		rows, err := db.Query(`
			SELECT DISTINCT package, price 
			FROM vip_purchases 
			GROUP BY package, price 
			ORDER BY price
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var packages []map[string]interface{}
		for rows.Next() {
			var pkg string
			var price float64
			rows.Scan(&pkg, &price)

			// package değerine göre süre hesapla
			duration := 30 // varsayılan
			switch pkg {
			case "monthly":
				duration = 30
			case "quarterly":
				duration = 90
			case "yearly":
				duration = 365
			}

			// Aktif abone ve satış sayılarını hesapla
			var subscriberCount, purchaseCount int
			db.QueryRow(`
				SELECT COUNT(DISTINCT user_id), COUNT(*) 
				FROM vip_purchases 
				WHERE package = $1 AND expiry_date > NOW()
			`, pkg).Scan(&subscriberCount, &purchaseCount)

			packages = append(packages, map[string]interface{}{
				"ID":              pkg, // package adını ID olarak kullan
				"Name":            pkg,
				"Price":           price,
				"DurationDays":    duration,
				"IsActive":        true,
				"SubscriberCount": subscriberCount,
				"PurchaseCount":   purchaseCount,
			})
		}

		// Son VIP satışlarını getir
		rows, err = db.Query(`
			SELECT vp.id, u.id, u.username, u.avatar, vp.package, vp.price, vp.purchased_at, vp.expiry_date
			FROM vip_purchases vp
			JOIN users u ON vp.user_id = u.id
			ORDER BY vp.purchased_at DESC
			LIMIT 10
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var purchases []map[string]interface{}
		for rows.Next() {
			var id, userID int
			var username, pkg, avatar string
			var price float64
			var purchasedAt, expiryDate time.Time

			rows.Scan(&id, &userID, &username, &avatar, &pkg, &price, &purchasedAt, &expiryDate)

			// Avatar yoksa varsayılan kullan
			if avatar == "" {
				avatar = "/static/images/default-avatar.png"
			}

			purchases = append(purchases, map[string]interface{}{
				"ID":          id,
				"UserID":      userID,
				"Username":    username,
				"UserAvatar":  avatar,
				"PlanName":    pkg,
				"Price":       price,
				"PurchasedAt": purchasedAt,
				"ExpiryDate":  expiryDate,
				"IsActive":    expiryDate.After(time.Now()),
			})
		}

		// Yakında bitecek VIP'ler
		rows, err = db.Query(`
			SELECT u.id, u.username, u.email, vp.package, vp.expiry_date
			FROM users u
			JOIN vip_purchases vp ON u.id = vp.user_id
			WHERE u.is_vip = true 
			AND vp.expiry_date BETWEEN NOW() AND NOW() + INTERVAL '7 days'
			ORDER BY vp.expiry_date ASC
			LIMIT 10
		`)

		var expiringVIPs []map[string]interface{}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var username, email, pkg string
				var expiryDate time.Time
				rows.Scan(&id, &username, &email, &pkg, &expiryDate)

				daysLeft := int(expiryDate.Sub(time.Now()).Hours() / 24)

				expiringVIPs = append(expiringVIPs, map[string]interface{}{
					"ID":         id,
					"Username":   username,
					"Email":      email,
					"PlanName":   pkg,
					"ExpiryDate": expiryDate,
					"DaysLeft":   daysLeft,
				})
			}
		}

		// Admin bilgileri
		admin := struct {
			Username string
			Role     string
			Avatar   string
		}{
			Username: username,
			Role:     role,
			Avatar:   "/static/images/avatar.png",
		}

		// Template fonksiyonlarını tanımla
		funcMap := template.FuncMap{
			"formatMoney": func(amount float64) string {
				return fmt.Sprintf("₺%.2f", amount)
			},
			"formatDate": func(t time.Time) string {
				return t.Format("02.01.2006")
			},
			"daysLeft": func(expiryDate time.Time) int {
				return int(expiryDate.Sub(time.Now()).Hours() / 24)
			},
			"calculateDiscount": func(days int) int {
				if days >= 365 {
					return 25
				} else if days >= 90 {
					return 15
				} else if days >= 30 {
					return 0
				}
				return 0
			},
		}

		// Template verisi
		data := struct {
			Title        string
			Active       string
			Admin        interface{}
			Stats        interface{}
			Packages     []map[string]interface{}
			Purchases    []map[string]interface{}
			ExpiringVIPs []map[string]interface{}
		}{
			Title:        "VIP Yönetimi - Admin Panel",
			Active:       "vip",
			Admin:        admin,
			Stats:        stats,
			Packages:     packages,
			Purchases:    purchases,
			ExpiringVIPs: expiringVIPs,
		}

		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/vip.html",
		)
		if err != nil {
			http.Error(w, "Template yüklenemedi: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template çalıştırılamadı: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// AdminStatsPage - İstatistik sayfası
func AdminStatsPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		var admin models.Admin
		admin.Username = username
		admin.Role = role
		admin.Avatar = "/static/images/avatar.png" // Varsayılan avatar
		data := struct {
			Title  string
			Active string
			Admin  models.Admin
		}{
			Title:  "Sistem İstatistikleri - Admin Panel",
			Active: "stats",
			Admin:  admin,
		}

		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/stats.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, data)
	}
}

// AdminLogsPage - Log görüntüleme sayfası
func AdminLogsPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		var admin models.Admin
		admin.Username = username
		admin.Role = role
		admin.Avatar = "/static/images/avatar.png" // Varsayılan avatar
		data := struct {
			Title  string
			Active string
			Admin  models.Admin
		}{
			Title:  "Sistem Logları - Admin Panel",
			Active: "logs",
			Admin:  admin,
		}

		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/logs.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, data)
	}
}

// AdminSettingsPage - Ayarlar sayfası

// AdminSubmissionsPage - Çözüm listesi sayfası
func AdminSubmissionsPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		var admin models.Admin
		admin.Username = username
		admin.Role = role
		admin.Avatar = "/static/images/avatar.png" // Varsayılan avatar

		data := struct {
			Title  string
			Active string
			Admin  models.Admin
		}{
			Title:  "Çözümler - Admin Panel",
			Active: "submissions",
			Admin:  admin,
		}

		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/submissions.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, data)
	}
}

// ==================== ADMIN API ENDPOINT'LERİ (JSON) ====================

// Admin Giriş API
func AdminLogin(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AdminLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Admin kullanıcısını kontrol et (önce username ile dene, olmazsa email ile)
		var admin models.User
		var role string
		err := db.QueryRow(`
            SELECT id, username, password_hash, role 
            FROM admins 
            WHERE (username = $1 OR email = $1) AND is_active = true
        `, req.Username).Scan(&admin.ID, &admin.Username, &admin.PasswordHash, &role)

		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Kullanıcı adı veya şifre hatalı",
			})
			return
		}

		// Şifre kontrolü
		err = bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password))
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Kullanıcı adı veya şifre hatalı",
			})
			return
		}

		// Admin session oluştur
		session, _ := store.Get(r, "admin_session")
		session.Values["authenticated"] = true
		session.Values["admin_id"] = admin.ID
		session.Values["username"] = admin.Username
		session.Values["role"] = role
		session.Options.MaxAge = 3600 // 1 saat
		session.Save(r, w)

		// JWT token oluştur
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"admin_id": admin.ID,
			"username": admin.Username,
			"role":     role,
			"exp":      time.Now().Add(1 * time.Hour).Unix(),
		})

		tokenString, _ := token.SignedString([]byte("admin-secret-key"))

		// Son giriş zamanını güncelle
		db.Exec("UPDATE admins SET last_login = NOW() WHERE id = $1", admin.ID)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"access_token":  tokenString,
			"refresh_token": "",
			"user": map[string]interface{}{
				"id":       admin.ID,
				"username": admin.Username,
				"role":     role,
			},
		})
	}
}

// AdminUsers API - Kullanıcı listesi (JSON)
func AdminUsers(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Session kontrolü
		session, _ := store.Get(r, "admin_session")
		if session.Values["username"] == nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}

		// Query parametrelerini al
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		search := r.URL.Query().Get("search")
		status := r.URL.Query().Get("status")
		vip := r.URL.Query().Get("vip")
		sort := r.URL.Query().Get("sort")

		// Default değerler
		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 20
		}

		// Base query
		query := `
            SELECT id, username, email, points, is_vip, is_active, 
                   COALESCE(last_login, created_at) as last_login, 
                   created_at, 
                   COALESCE(full_name, '') as full_name,
                   COALESCE(avatar, '/static/images/default-avatar.png') as avatar
            FROM users
            WHERE 1=1
        `

		countQuery := `SELECT COUNT(*) FROM users WHERE 1=1`

		var args []interface{}
		var countArgs []interface{}
		argCount := 1

		// Arama filtresi
		if search != "" {
			query += ` AND (username ILIKE $` + strconv.Itoa(argCount) +
				` OR email ILIKE $` + strconv.Itoa(argCount) +
				` OR COALESCE(full_name, '') ILIKE $` + strconv.Itoa(argCount) + `)`
			countQuery += ` AND (username ILIKE $` + strconv.Itoa(argCount) +
				` OR email ILIKE $` + strconv.Itoa(argCount) +
				` OR COALESCE(full_name, '') ILIKE $` + strconv.Itoa(argCount) + `)`
			args = append(args, "%"+search+"%")
			countArgs = append(countArgs, "%"+search+"%")
			argCount++
		}

		// Durum filtresi (active/inactive)
		if status == "active" {
			query += ` AND is_active = true`
			countQuery += ` AND is_active = true`
		} else if status == "inactive" {
			query += ` AND is_active = false`
			countQuery += ` AND is_active = false`
		}

		// VIP filtresi
		if vip == "vip" {
			query += ` AND is_vip = true`
			countQuery += ` AND is_vip = true`
		} else if vip == "normal" {
			query += ` AND is_vip = false`
			countQuery += ` AND is_vip = false`
		}

		// Sıralama
		switch sort {
		case "points_desc":
			query += ` ORDER BY points DESC`
		case "points_asc":
			query += ` ORDER BY points ASC`
		case "name_asc":
			query += ` ORDER BY username ASC`
		case "name_desc":
			query += ` ORDER BY username DESC`
		case "oldest":
			query += ` ORDER BY created_at ASC`
		default: // "date_desc" veya varsayılan
			query += ` ORDER BY created_at DESC`
		}

		// Toplam sayıyı al
		var total int
		err := db.QueryRow(countQuery, countArgs...).Scan(&total)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Sayfalama
		query += ` LIMIT $` + strconv.Itoa(argCount) +
			` OFFSET $` + strconv.Itoa(argCount+1)
		args = append(args, limit, (page-1)*limit)

		// Kullanıcıları getir
		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []models.User
		for rows.Next() {
			var u models.User
			var lastLogin sql.NullTime
			var fullName sql.NullString
			var avatar sql.NullString

			err := rows.Scan(
				&u.ID,
				&u.Username,
				&u.Email,
				&u.Points,
				&u.IsVIP,
				&u.IsActive,
				&lastLogin,
				&u.CreatedAt,
				&fullName,
				&avatar,
			)
			if err != nil {
				continue
			}

			// Null değerleri kontrol et
			if lastLogin.Valid {
				u.LastLogin = lastLogin.Time
			}
			if fullName.Valid {
				u.FullName = fullName.String
			}
			if avatar.Valid {
				u.Avatar = avatar.String
			} else {
				u.Avatar = "/static/images/avatar.png"
			}

			users = append(users, u)
		}

		// İstatistikleri al (template'de kullanılan Stats struct'ı için)
		var stats struct {
			TotalUsers  int
			ActiveUsers int
			VIPUsers    int
			NewToday    int
		}

		// Aktif kullanıcı sayısı (son 24 saat)
		db.QueryRow(`
            SELECT COUNT(*) FROM users 
            WHERE last_login > NOW() - INTERVAL '24 hours'
        `).Scan(&stats.ActiveUsers)

		// VIP kullanıcı sayısı
		db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_vip = true`).Scan(&stats.VIPUsers)

		// Bugün kaydolanlar
		db.QueryRow(`
            SELECT COUNT(*) FROM users 
            WHERE DATE(created_at) = CURRENT_DATE
        `).Scan(&stats.NewToday)

		// Toplam kullanıcı
		stats.TotalUsers = total

		// Sayfalama hesaplamaları
		totalPages := (total + limit - 1) / limit
		if totalPages < 1 {
			totalPages = 1
		}

		// Sayfa numaralarını oluştur (5 sayfa göster)
		var pages []int
		startPage := max(1, page-2)
		endPage := min(totalPages, page+2)

		for i := startPage; i <= endPage; i++ {
			pages = append(pages, i)
		}

		// Admin bilgilerini al
		admin := models.Admin{
			Username: session.Values["username"].(string),
			Role:     session.Values["role"].(string),
			Avatar:   "/static/images/avatar.png", // Varsayılan avatar
		}

		// Template data
		data := struct {
			Title      string
			Active     string
			Admin      models.Admin
			Users      []models.User
			Stats      interface{}
			Pagination struct {
				CurrentPage int
				TotalPages  int
				TotalItems  int
				Start       int
				End         int
				HasPrev     bool
				HasNext     bool
				PrevPage    int
				NextPage    int
				Pages       []int
			}
			Filters struct {
				Search string
				Status string
				VIP    string
				Sort   string
			}
		}{
			Title:  "Kullanıcı Yönetimi - Admin Panel",
			Active: "users",
			Admin:  admin,
			Users:  users,
			Stats:  stats,
		}

		// Sayfalama bilgileri
		data.Pagination.CurrentPage = page
		data.Pagination.TotalPages = totalPages
		data.Pagination.TotalItems = total
		data.Pagination.Start = (page-1)*limit + 1
		data.Pagination.End = min(page*limit, total)
		data.Pagination.HasPrev = page > 1
		data.Pagination.HasNext = page < totalPages
		data.Pagination.PrevPage = page - 1
		data.Pagination.NextPage = page + 1
		data.Pagination.Pages = pages

		// Filtre bilgileri
		data.Filters.Search = search
		data.Filters.Status = status
		data.Filters.VIP = vip
		data.Filters.Sort = sort

		// Template'i parse et
		tmpl, err := template.ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/users.html",
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Template'i execute et
		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// Yardımcı fonksiyonlar
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AdminUserDetail API - Kullanıcı detayı (JSON)
func AdminUserDetail(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		var user models.User
		err := db.QueryRow(`
            SELECT id, username, email, avatar, bio, location, website,
                   points, rank, is_vip, vip_expiry_date, is_active,
                   created_at, last_login
            FROM users
            WHERE id = $1
        `, userID).Scan(
			&user.ID, &user.Username, &user.Email, &user.Avatar, &user.Bio,
			&user.Location, &user.Website, &user.Points, &user.Rank,
			&user.IsVIP, &user.VIPExpiryDate, &user.IsActive,
			&user.CreatedAt, &user.LastLogin,
		)

		if err != nil {
			http.Error(w, "Kullanıcı bulunamadı", http.StatusNotFound)
			return
		}

		// Kullanıcı istatistikleri
		var stats struct {
			TotalSubmissions    int `json:"total_submissions"`
			AcceptedSubmissions int `json:"accepted_submissions"`
			TotalMachines       int `json:"total_machines"`
			TotalPoints         int `json:"total_points"`
		}

		db.QueryRow(`
            SELECT 
                COUNT(*) as total_submissions,
                SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as accepted,
                COUNT(DISTINCT machine_id) as machines,
                COALESCE(SUM(points), 0) as points
            FROM submissions
            WHERE user_id = $1
        `, userID).Scan(&stats.TotalSubmissions, &stats.AcceptedSubmissions, &stats.TotalMachines, &stats.TotalPoints)

		// Son aktiviteler
		rows, err := db.Query(`
            SELECT s.id, m.name, q.title, s.status, s.created_at
            FROM submissions s
            JOIN machines m ON s.machine_id = m.id
            JOIN machine_questions q ON s.question_id = q.id
            WHERE s.user_id = $1
            ORDER BY s.created_at DESC
            LIMIT 20
        `, userID)

		var submissions []models.Submission
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var s models.Submission
				rows.Scan(&s.ID, &s.MachineName, &s.QuestionTitle, &s.Status, &s.SubmittedAt)
				submissions = append(submissions, s)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":        user,
			"stats":       stats,
			"submissions": submissions,
		})
	}
}

// AdminUpdateUser API - Kullanıcı güncelle (JSON)
func AdminUpdateUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		// Kullanıcıyı güncelle
		query := "UPDATE users SET "
		var args []interface{}
		argCount := 1

		allowedFields := []string{"is_vip", "is_active", "points", "rank"}
		for _, field := range allowedFields {
			if val, ok := updates[field]; ok {
				if argCount > 1 {
					query += ", "
				}
				query += field + " = $" + strconv.Itoa(argCount)
				args = append(args, val)
				argCount++
			}
		}

		if argCount > 1 {
			query += " WHERE id = $" + strconv.Itoa(argCount)
			args = append(args, userID)

			_, err = tx.Exec(query, args...)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// Şifre değiştirme
		if newPassword, ok := updates["new_password"]; ok && newPassword != "" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword.(string)), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			_, err = tx.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", hashedPassword, userID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		tx.Commit()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Kullanıcı güncellendi",
		})
	}
}

// AdminToggleUserStatus API - Kullanıcı durumunu değiştir
func AdminToggleUserStatus(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		_, err := db.Exec("UPDATE users SET is_active = NOT is_active WHERE id = $1", userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Kullanıcı durumu güncellendi",
		})
	}
}

// AdminToggleUserVIP API - Kullanıcı VIP durumunu değiştir
func AdminToggleUserVIP(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		_, err := db.Exec("UPDATE users SET is_vip = NOT is_vip WHERE id = $1", userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Kullanıcı VIP durumu güncellendi",
		})
	}
}

// AdminResetPassword API - Şifre sıfırla
func AdminResetPassword(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		// Rastgele şifre oluştur
		newPassword := generateRandomPassword(10)
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

		_, err := db.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", hashedPassword, userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"password": newPassword,
			"message":  "Şifre sıfırlandı",
		})
	}
}

// AdminDeleteUser API - Kullanıcı sil
func AdminDeleteUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		_, err := db.Exec("DELETE FROM users WHERE id = $1", userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Kullanıcı silindi",
		})
	}
}

// AdminCreateUser API - Yeni kullanıcı oluştur
// AdminCreateUser API - Yeni kullanıcı oluştur
func AdminCreateUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Geçici bir struct ile şifreyi al
		var requestData struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"` // Şifreyi burada al
			FullName string `json:"fullname"`
			IsActive bool   `json:"is_active"`
		}

		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Şifreyi hashle
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Şifre hashlenemedi", http.StatusInternalServerError)
			return
		}

		// Kullanıcıyı veritabanına ekle
		var userID int
		err = db.QueryRow(`
            INSERT INTO users (username, email, password_hash, fullname, is_active, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING id
        `, requestData.Username, requestData.Email, string(hashedPassword),
			requestData.FullName, requestData.IsActive).Scan(&userID)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"user_id": userID,
			"message": "Kullanıcı oluşturuldu",
		})
	}
}

// AdminMachines API - Makine listesi (JSON)
func AdminMachines(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		difficulty := r.URL.Query().Get("difficulty")

		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 20
		}

		query := `
            SELECT m.id, m.name, m.description, m.difficulty, m.points_reward,
                   m.is_vip_only, m.is_active, m.created_at,
                   COALESCE(u.username, 'System') as creator,
                   COUNT(DISTINCT mq.id) as question_count,
                   COUNT(DISTINCT s.id) as submission_count
            FROM machines m
            LEFT JOIN users u ON m.creator_id = u.id
            LEFT JOIN machine_questions mq ON m.id = mq.machine_id
            LEFT JOIN submissions s ON m.id = s.machine_id
            WHERE 1=1
        `
		var args []interface{}
		argCount := 1

		if difficulty != "" && difficulty != "all" {
			query += ` AND m.difficulty = $` + strconv.Itoa(argCount)
			args = append(args, difficulty)
			argCount++
		}

		query += ` GROUP BY m.id, u.username`

		// Toplam sayı
		var total int
		countQuery := "SELECT COUNT(*) FROM (" + query + ") AS count"
		db.QueryRow(countQuery, args...).Scan(&total)

		// Sayfalama
		query += ` ORDER BY m.created_at DESC 
                   LIMIT $` + strconv.Itoa(argCount) + ` 
                   OFFSET $` + strconv.Itoa(argCount+1)
		args = append(args, limit, (page-1)*limit)

		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var machines []map[string]interface{}
		for rows.Next() {
			var m struct {
				ID              int
				Name            string
				Description     string
				Difficulty      string
				PointsReward    int
				IsVIPOnly       bool
				IsActive        bool
				CreatedAt       time.Time
				Creator         string
				QuestionCount   int
				SubmissionCount int
			}
			rows.Scan(
				&m.ID, &m.Name, &m.Description, &m.Difficulty, &m.PointsReward,
				&m.IsVIPOnly, &m.IsActive, &m.CreatedAt,
				&m.Creator, &m.QuestionCount, &m.SubmissionCount,
			)
			machines = append(machines, map[string]interface{}{
				"id":               m.ID,
				"name":             m.Name,
				"description":      m.Description,
				"difficulty":       m.Difficulty,
				"points_reward":    m.PointsReward,
				"is_vip_only":      m.IsVIPOnly,
				"is_active":        m.IsActive,
				"created_at":       m.CreatedAt,
				"creator":          m.Creator,
				"question_count":   m.QuestionCount,
				"submission_count": m.SubmissionCount,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"machines": machines,
			"pagination": map[string]interface{}{
				"current_page": page,
				"total_pages":  (total + limit - 1) / limit,
				"total":        total,
				"limit":        limit,
			},
		})
	}
}

// AdminCreateMachine API - Makine oluştur (JSON)
func AdminCreateMachine(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var machine models.Machine
		if err := json.NewDecoder(r.Body).Decode(&machine); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Session'dan admin ID'yi al
		session, _ := store.Get(r, "admin_session")
		adminID, ok := session.Values["admin_id"].(int)
		if !ok {
			http.Error(w, "Yetkisiz erişim", http.StatusUnauthorized)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		// Makineyi ekle
		var machineID int
		err = tx.QueryRow(`
            INSERT INTO machines (name, description, difficulty, points_reward, 
                                 is_vip_only, creator_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            RETURNING id
        `, machine.Name, machine.Description, machine.Difficulty,
			machine.PointsReward, machine.IsVIPOnly, adminID).Scan(&machineID)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Soruları ekle
		for i, q := range machine.Questions {
			_, err = tx.Exec(`
                INSERT INTO machine_questions (machine_id, question_order, title, 
                                              description, flag_hash, points_reward, hint, hint_cost)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            `, machineID, i+1, q.Title, q.Description, q.FlagHash,
				q.PointsReward, q.Hint, q.HintCost)

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		tx.Commit()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"message":    "Makine başarıyla oluşturuldu",
			"machine_id": machineID,
		})
	}
}

// AdminUpdateMachine API - Makine güncelle (JSON)
func AdminUpdateMachine(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		machineID := vars["id"]

		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		query := "UPDATE machines SET "
		var args []interface{}
		argCount := 1

		allowedFields := []string{"name", "description", "difficulty", "points_reward", "is_vip_only", "is_active"}
		for _, field := range allowedFields {
			if val, ok := updates[field]; ok {
				if argCount > 1 {
					query += ", "
				}
				query += field + " = $" + strconv.Itoa(argCount)
				args = append(args, val)
				argCount++
			}
		}

		if argCount > 1 {
			query += " WHERE id = $" + strconv.Itoa(argCount)
			args = append(args, machineID)

			_, err := db.Exec(query, args...)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Makine güncellendi",
		})
	}
}

// AdminToggleMachine API - Makine durumunu değiştir
func AdminToggleMachine(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		machineID := vars["id"]

		_, err := db.Exec("UPDATE machines SET is_active = NOT is_active WHERE id = $1", machineID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Makine durumu güncellendi",
		})
	}
}

// AdminDeleteMachine API - Makine sil
func AdminDeleteMachine(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		machineID := vars["id"]

		_, err := db.Exec("DELETE FROM machines WHERE id = $1", machineID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Makine silindi",
		})
	}
}

// AdminQuestions API - Soru listesi (JSON)
func AdminQuestions(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		machineID := r.URL.Query().Get("machine_id")

		query := `
            SELECT q.id, q.machine_id, q.question_order, q.title, 
                   q.description, q.points_reward, q.hint, q.hint_cost, q.is_active,
                   m.name as machine_name,
                   COUNT(s.id) as submission_count,
                   COUNT(CASE WHEN s.status = 'accepted' THEN 1 END) as accepted_count
            FROM machine_questions q
            JOIN machines m ON q.machine_id = m.id
            LEFT JOIN submissions s ON q.id = s.question_id
            WHERE 1=1
        `
		var args []interface{}
		argCount := 1

		if machineID != "" {
			query += ` AND q.machine_id = $` + strconv.Itoa(argCount)
			args = append(args, machineID)
			argCount++
		}

		query += ` GROUP BY q.id, m.id ORDER BY q.machine_id, q.question_order`

		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var questions []map[string]interface{}
		for rows.Next() {
			var q struct {
				ID              int
				MachineID       int
				QuestionOrder   int
				Title           string
				Description     string
				PointsReward    int
				Hint            string
				HintCost        int
				IsActive        bool
				MachineName     string
				SubmissionCount int
				AcceptedCount   int
			}
			rows.Scan(
				&q.ID, &q.MachineID, &q.QuestionOrder, &q.Title,
				&q.Description, &q.PointsReward, &q.Hint, &q.HintCost, &q.IsActive,
				&q.MachineName, &q.SubmissionCount, &q.AcceptedCount,
			)
			questions = append(questions, map[string]interface{}{
				"id":               q.ID,
				"machine_id":       q.MachineID,
				"machine_name":     q.MachineName,
				"question_order":   q.QuestionOrder,
				"title":            q.Title,
				"description":      q.Description,
				"points_reward":    q.PointsReward,
				"hint":             q.Hint,
				"hint_cost":        q.HintCost,
				"is_active":        q.IsActive,
				"submission_count": q.SubmissionCount,
				"accepted_count":   q.AcceptedCount,
				"success_rate":     float64(q.AcceptedCount) / float64(q.SubmissionCount) * 100,
			})
		}

		json.NewEncoder(w).Encode(questions)
	}
}

// AdminCreateQuestion API - Yeni soru oluştur
// AdminCreateQuestion API - Yeni soru oluştur
func AdminCreateQuestion(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Geçici bir struct ile verileri al
		var requestData struct {
			MachineID     int    `json:"machine_id"`
			Title         string `json:"title"`
			Description   string `json:"description"`
			Flag          string `json:"flag"`      // Düz flag
			FlagHash      string `json:"flag_hash"` // Hash'lenmiş flag (opsiyonel)
			PointsReward  int    `json:"points_reward"`
			Hint          string `json:"hint"`
			HintCost      int    `json:"hint_cost"`
			IsActive      bool   `json:"is_active"`
			QuestionOrder int    `json:"question_order"`
		}

		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Flag'i hashle (eğer düz flag geldiyse)
		flagHash := requestData.FlagHash
		if requestData.Flag != "" {
			hashed, err := bcrypt.GenerateFromPassword([]byte(requestData.Flag), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Flag hashlenemedi", http.StatusInternalServerError)
				return
			}
			flagHash = string(hashed)
		}

		// Sıra numarası yoksa varsayılan ata
		questionOrder := requestData.QuestionOrder
		if questionOrder == 0 {
			// Mevcut soru sayısını bul
			var count int
			db.QueryRow("SELECT COUNT(*) FROM machine_questions WHERE machine_id = $1",
				requestData.MachineID).Scan(&count)
			questionOrder = count + 1
		}

		// Soruyu veritabanına ekle
		var questionID int
		err := db.QueryRow(`
            INSERT INTO machine_questions (
                machine_id, question_order, title, description, flag_hash, 
                points_reward, hint, hint_cost, is_active, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            RETURNING id
        `,
			requestData.MachineID,
			questionOrder,
			requestData.Title,
			requestData.Description,
			flagHash,
			requestData.PointsReward,
			requestData.Hint,
			requestData.HintCost,
			requestData.IsActive,
		).Scan(&questionID)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Makinenin toplam soru sayısını güncelle
		_, err = db.Exec(`
            UPDATE machines 
            SET total_questions = (
                SELECT COUNT(*) FROM machine_questions WHERE machine_id = $1
            ) WHERE id = $1
        `, requestData.MachineID)

		if err != nil {
			// Hata önemli değil, devam et
			log.Println("Makine soru sayısı güncellenemedi:", err)
		}

		// Başarılı yanıt
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"question_id": questionID,
			"message":     "Soru başarıyla oluşturuldu",
		})
	}
}

// AdminUpdateQuestion API - Soru güncelle
// AdminUpdateQuestion API - Soru güncelle (JSON)
func AdminUpdateQuestion(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		questionIDStr := vars["id"] // Bu string

		// String'i int'e çevir
		questionID, err := strconv.Atoi(questionIDStr)
		if err != nil {
			http.Error(w, "Geçersiz soru ID", http.StatusBadRequest)
			return
		}

		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// İzin verilen alanlar
		allowedFields := []string{
			"title", "description", "flag_hash", "points_reward",
			"hint", "hint_cost", "is_active", "question_order",
		}

		// Güncelleme sorgusunu oluştur
		query := "UPDATE machine_questions SET "
		var args []interface{}
		argCount := 1

		for _, field := range allowedFields {
			if val, ok := updates[field]; ok {
				if argCount > 1 {
					query += ", "
				}
				query += field + " = $" + strconv.Itoa(argCount)
				args = append(args, val)
				argCount++
			}
		}

		// Eğer flag güncellenmişse hash'le
		if flag, ok := updates["flag"]; ok && flag != "" {
			if argCount > 1 {
				query += ", "
			}
			hashedFlag, err := bcrypt.GenerateFromPassword([]byte(flag.(string)), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Flag hashlenemedi", http.StatusInternalServerError)
				return
			}
			query += "flag_hash = $" + strconv.Itoa(argCount)
			args = append(args, string(hashedFlag))
			argCount++
		}

		// Güncellenecek alan yoksa hata döndür
		if argCount == 1 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Güncellenecek alan bulunamadı",
			})
			return
		}

		// WHERE koşulunu ekle
		query += " WHERE id = $" + strconv.Itoa(argCount)
		args = append(args, questionID) // int olarak kullan

		// Transaction başlat
		tx, err := db.Begin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		// Sorguyu çalıştır
		result, err := tx.Exec(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Etkilenen satır sayısını kontrol et
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Soru bulunamadı",
			})
			return
		}

		// Log kaydı ekle
		session, _ := store.Get(r, "admin_session")
		adminID := session.Values["admin_id"].(int)
		adminUsername := session.Values["username"].(string)

		_, err = tx.Exec(`
            INSERT INTO admin_logs (admin_id, action_type, target_id, details, created_at)
            VALUES ($1, $2, $3, $4, NOW())
        `, adminID, "UPDATE_QUESTION", questionID, // questionID int
			adminUsername+" soru #"+strconv.Itoa(questionID)+" güncelledi") // Burada int kullan

		if err != nil {
			// Log hatası önemli değil, devam et
			log.Println("Log kaydı eklenemedi:", err)
		}

		// Transaction'ı commit et
		err = tx.Commit()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Başarılı yanıt
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Soru başarıyla güncellendi",
		})
	}
}

// AdminToggleQuestion API - Soru durumunu değiştir
func AdminToggleQuestion(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		questionID := vars["id"]

		_, err := db.Exec("UPDATE machine_questions SET is_active = NOT is_active WHERE id = $1", questionID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Soru durumu güncellendi",
		})
	}
}

// AdminDeleteQuestion API - Soru sil
func AdminDeleteQuestion(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		questionID := vars["id"]

		_, err := db.Exec("DELETE FROM machine_questions WHERE id = $1", questionID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Soru silindi",
		})
	}
}

// AdminVIPManagement API - VIP yönetimi (JSON)
// VIP Yönetimi
func AdminVIPManagement(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// VIP kullanıcılar
		rows, err := db.Query(`
            SELECT u.id, u.username, u.email, u.vip_expiry_date,
                   vp.package, vp.price, vp.purchased_at
            FROM users u
            JOIN vip_purchases vp ON u.id = vp.user_id
            WHERE u.is_vip = true
            ORDER BY vp.purchased_at DESC
        `)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var vipUsers []map[string]interface{}
		for rows.Next() {
			var vip struct {
				ID          int
				Username    string
				Email       string
				ExpiryDate  *time.Time
				Package     string
				Price       float64
				PurchasedAt time.Time
			}
			rows.Scan(&vip.ID, &vip.Username, &vip.Email, &vip.ExpiryDate,
				&vip.Package, &vip.Price, &vip.PurchasedAt)

			daysLeft := 0
			if vip.ExpiryDate != nil {
				daysLeft = int(time.Until(*vip.ExpiryDate).Hours() / 24)
			}

			vipUsers = append(vipUsers, map[string]interface{}{
				"id":           vip.ID,
				"username":     vip.Username,
				"email":        vip.Email,
				"expiry_date":  vip.ExpiryDate,
				"days_left":    daysLeft,
				"package":      vip.Package,
				"price":        vip.Price,
				"purchased_at": vip.PurchasedAt,
			})
		}

		// VIP istatistikleri
		var stats struct {
			TotalRevenue   float64 `json:"total_revenue"`
			MonthlyRevenue float64 `json:"monthly_revenue"`
			TotalVIPUsers  int     `json:"total_vip_users"`
			AvgVIPDuration float64 `json:"avg_vip_duration"`
		}

		db.QueryRow(`
            SELECT 
                COALESCE(SUM(price), 0) as total_revenue,
                COALESCE(SUM(CASE WHEN purchased_at > NOW() - INTERVAL '30 days' THEN price ELSE 0 END), 0) as monthly_revenue,
                COUNT(DISTINCT user_id) as total_vip_users,
                COALESCE(AVG(EXTRACT(DAY FROM (expiry_date - purchased_at))), 0) as avg_duration
            FROM vip_purchases
        `).Scan(&stats.TotalRevenue, &stats.MonthlyRevenue, &stats.TotalVIPUsers, &stats.AvgVIPDuration)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"vip_users": vipUsers,
			"stats":     stats,
		})
	}
}

// AdminVIPPlans API - VIP planları listesi
func AdminVIPPlans(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
            SELECT id, name, price, duration_days, features, is_active
            FROM vip_plans ORDER BY price
        `)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var plans []map[string]interface{}
		for rows.Next() {
			var id int
			var name string
			var price float64
			var duration int
			var features string
			var isActive bool
			rows.Scan(&id, &name, &price, &duration, &features, &isActive)
			plans = append(plans, map[string]interface{}{
				"id":            id,
				"name":          name,
				"price":         price,
				"duration_days": duration,
				"features":      features,
				"is_active":     isActive,
			})
		}

		json.NewEncoder(w).Encode(plans)
	}
}

// AdminVIPPurchases API - VIP satın alımları
func AdminVIPPurchases(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
            SELECT vp.id, u.username, vp.plan_name, vp.price, vp.purchased_at, vp.expiry_date
            FROM vip_purchases vp
            JOIN users u ON vp.user_id = u.id
            ORDER BY vp.purchased_at DESC
            LIMIT 50
        `)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var purchases []map[string]interface{}
		for rows.Next() {
			var id int
			var username string
			var planName string
			var price float64
			var purchasedAt time.Time
			var expiryDate *time.Time
			rows.Scan(&id, &username, &planName, &price, &purchasedAt, &expiryDate)
			purchases = append(purchases, map[string]interface{}{
				"id":           id,
				"username":     username,
				"plan_name":    planName,
				"price":        price,
				"purchased_at": purchasedAt,
				"expiry_date":  expiryDate,
			})
		}

		json.NewEncoder(w).Encode(purchases)
	}
}

// AdminSystemStats API - Sistem istatistikleri (JSON)
func AdminSystemStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Günlük istatistikler
		rows, err := db.Query(`
            SELECT 
                DATE(created_at) as date,
                COUNT(DISTINCT user_id) as active_users,
                COUNT(*) as total_submissions,
                COUNT(CASE WHEN status = 'accepted' THEN 1 END) as accepted_submissions
            FROM submissions
            WHERE created_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        `)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var dailyStats []map[string]interface{}
		for rows.Next() {
			var date time.Time
			var activeUsers, totalSubmissions, acceptedSubmissions int
			rows.Scan(&date, &activeUsers, &totalSubmissions, &acceptedSubmissions)

			dailyStats = append(dailyStats, map[string]interface{}{
				"date":                 date,
				"active_users":         activeUsers,
				"total_submissions":    totalSubmissions,
				"accepted_submissions": acceptedSubmissions,
				"success_rate":         float64(acceptedSubmissions) / float64(totalSubmissions) * 100,
			})
		}

		// Zorluk dağılımı
		rows, err = db.Query(`
            SELECT difficulty, COUNT(*) as count
            FROM machines
            WHERE is_active = true
            GROUP BY difficulty
        `)

		var difficultyStats []map[string]interface{}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var difficulty string
				var count int
				rows.Scan(&difficulty, &count)
				difficultyStats = append(difficultyStats, map[string]interface{}{
					"difficulty": difficulty,
					"count":      count,
				})
			}
		}

		// Coğrafi dağılım
		rows, err = db.Query(`
            SELECT country, COUNT(*) as count
            FROM users
            WHERE country IS NOT NULL
            GROUP BY country
            ORDER BY count DESC
            LIMIT 10
        `)

		var countryStats []map[string]interface{}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var country string
				var count int
				rows.Scan(&country, &count)
				countryStats = append(countryStats, map[string]interface{}{
					"country": country,
					"count":   count,
				})
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"daily_stats":      dailyStats,
			"difficulty_stats": difficultyStats,
			"country_stats":    countryStats,
		})
	}
}

// AdminDailyStats API - Günlük istatistikler
func AdminDailyStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as submissions,
                COUNT(CASE WHEN status = 'accepted' THEN 1 END) as accepted
            FROM submissions
            WHERE created_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY date
        `)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var dailyStats []map[string]interface{}
		for rows.Next() {
			var date time.Time
			var submissions, accepted int
			rows.Scan(&date, &submissions, &accepted)
			dailyStats = append(dailyStats, map[string]interface{}{
				"date":         date,
				"submissions":  submissions,
				"accepted":     accepted,
				"success_rate": float64(accepted) / float64(submissions) * 100,
			})
		}

		json.NewEncoder(w).Encode(dailyStats)
	}
}

// AdminChartData API - Grafik verileri
func AdminChartData(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Son 7 günlük kullanıcı ve çözüm verileri
		rows, err := db.Query(`
            SELECT 
                TO_CHAR(date, 'DD/MM') as label,
                COALESCE(users, 0) as users,
                COALESCE(submissions, 0) as submissions
            FROM generate_series(
                CURRENT_DATE - INTERVAL '6 days', 
                CURRENT_DATE, 
                '1 day'
            ) AS date
            LEFT JOIN (
                SELECT DATE(created_at) as day, COUNT(*) as users
                FROM users
                WHERE created_at > CURRENT_DATE - INTERVAL '7 days'
                GROUP BY day
            ) u ON date = u.day
            LEFT JOIN (
                SELECT DATE(created_at) as day, COUNT(*) as submissions
                FROM submissions
                WHERE created_at > CURRENT_DATE - INTERVAL '7 days'
                GROUP BY day
            ) s ON date = s.day
            ORDER BY date
        `)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var labels []string
		var userData []int
		var submissionData []int

		for rows.Next() {
			var label string
			var users, submissions int
			rows.Scan(&label, &users, &submissions)
			labels = append(labels, label)
			userData = append(userData, users)
			submissionData = append(submissionData, submissions)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"labels": labels,
			"datasets": []map[string]interface{}{
				{
					"label": "Yeni Kullanıcı",
					"data":  userData,
				},
				{
					"label": "Çözümler",
					"data":  submissionData,
				},
			},
		})
	}
}

// AdminLogs API - Log listesi (JSON)
func AdminLogs(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		logType := r.URL.Query().Get("type")

		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 50
		}

		query := `
            SELECT id, action_type, user_id, username, ip_address, details, created_at
            FROM admin_logs
            WHERE 1=1
        `
		var args []interface{}
		argCount := 1

		if logType != "" && logType != "all" {
			query += ` AND action_type = $` + strconv.Itoa(argCount)
			args = append(args, logType)
			argCount++
		}

		// Toplam sayı
		var total int
		countQuery := "SELECT COUNT(*) FROM (" + query + ") AS count"
		db.QueryRow(countQuery, args...).Scan(&total)

		// Sayfalama
		query += ` ORDER BY created_at DESC 
                   LIMIT $` + strconv.Itoa(argCount) + ` 
                   OFFSET $` + strconv.Itoa(argCount+1)
		args = append(args, limit, (page-1)*limit)

		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var logs []map[string]interface{}
		for rows.Next() {
			var log struct {
				ID         int
				ActionType string
				UserID     *int
				Username   *string
				IPAddress  string
				Details    string
				CreatedAt  time.Time
			}
			rows.Scan(&log.ID, &log.ActionType, &log.UserID, &log.Username,
				&log.IPAddress, &log.Details, &log.CreatedAt)

			logs = append(logs, map[string]interface{}{
				"id":          log.ID,
				"action_type": log.ActionType,
				"user_id":     log.UserID,
				"username":    log.Username,
				"ip_address":  log.IPAddress,
				"details":     log.Details,
				"created_at":  log.CreatedAt,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs": logs,
			"pagination": map[string]interface{}{
				"current_page": page,
				"total_pages":  (total + limit - 1) / limit,
				"total":        total,
				"limit":        limit,
			},
		})
	}
}

// AdminExportLogs API - Logları dışa aktar
func AdminExportLogs(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
            SELECT created_at, action_type, username, ip_address, details
            FROM admin_logs
            ORDER BY created_at DESC
            LIMIT 1000
        `)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment;filename=logs.csv")

		// CSV başlıkları
		w.Write([]byte("Tarih,İşlem Tipi,Kullanıcı,IP Adresi,Detay\n"))

		for rows.Next() {
			var createdAt time.Time
			var actionType, username, ipAddress, details string
			rows.Scan(&createdAt, &actionType, &username, &ipAddress, &details)
			w.Write([]byte(createdAt.Format("2006-01-02 15:04:05") + "," +
				actionType + "," + username + "," + ipAddress + "," + details + "\n"))
		}
	}
}

// AdminSettings API - Ayarlar (JSON)
func AdminSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// Ayarları getir
			var settings map[string]interface{}
			rows, err := db.Query("SELECT key, value FROM system_settings")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			settings = make(map[string]interface{})
			for rows.Next() {
				var key, value string
				rows.Scan(&key, &value)
				settings[key] = value
			}

			json.NewEncoder(w).Encode(settings)
		} else if r.Method == "POST" {
			// Ayarları güncelle
			var updates map[string]string
			if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
				http.Error(w, "Geçersiz istek", http.StatusBadRequest)
				return
			}

			tx, err := db.Begin()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer tx.Rollback()

			for key, value := range updates {
				_, err = tx.Exec(`
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ($1, $2, NOW())
                    ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
                `, key, value)

				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}

			tx.Commit()

			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Ayarlar güncellendi",
			})
		}
	}
}

// AdminUpdateSettings API - Ayarları güncelle
func AdminUpdateSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var updates map[string]string
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		for key, value := range updates {
			_, err = tx.Exec(`
                INSERT INTO system_settings (key, value, updated_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
            `, key, value)

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		tx.Commit()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Ayarlar güncellendi",
		})
	}
}

// AdminLogout API - Çıkış (JSON)
func AdminLogout(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "admin_session")
		session.Values["authenticated"] = false
		session.Options.MaxAge = -1
		session.Save(r, w)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Çıkış yapıldı",
		})
	}
}

// Yardımcı fonksiyonlar
func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(1)
	}
	return string(password)
}

// AdminCreateVIPPlan API - Yeni VIP planı oluştur
func AdminCreateVIPPlan(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var plan struct {
			Name        string   `json:"name"`
			Price       float64  `json:"price"`
			Duration    int      `json:"duration_days"`
			Features    []string `json:"features"`
			Description string   `json:"description"`
			IsActive    bool     `json:"is_active"`
		}

		if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Validasyon
		if plan.Name == "" || plan.Price <= 0 || plan.Duration <= 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Plan adı, fiyat ve süre zorunludur",
			})
			return
		}

		// Features array'ini string'e çevir
		featuresJSON, err := json.Marshal(plan.Features)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var planID int
		err = db.QueryRow(`
            INSERT INTO vip_plans (name, price, duration_days, features, description, is_active, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            RETURNING id
        `, plan.Name, plan.Price, plan.Duration, string(featuresJSON),
			plan.Description, plan.IsActive).Scan(&planID)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"plan_id": planID,
			"message": "VIP planı oluşturuldu",
		})
	}
}

// AdminUpdateVIPPlan API - VIP planı güncelle
func AdminUpdateVIPPlan(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		planID, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Geçersiz plan ID", http.StatusBadRequest)
			return
		}

		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Features varsa JSON'a çevir
		if features, ok := updates["features"]; ok {
			if featuresList, ok := features.([]interface{}); ok {
				featuresJSON, err := json.Marshal(featuresList)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				updates["features"] = string(featuresJSON)
			}
		}

		// Güncelleme sorgusunu oluştur
		query := "UPDATE vip_plans SET "
		var args []interface{}
		argCount := 1
		allowedFields := []string{"name", "price", "duration_days", "features", "description", "is_active"}

		for _, field := range allowedFields {
			if val, ok := updates[field]; ok {
				if argCount > 1 {
					query += ", "
				}
				query += field + " = $" + strconv.Itoa(argCount)
				args = append(args, val)
				argCount++
			}
		}

		if argCount == 1 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Güncellenecek alan bulunamadı",
			})
			return
		}

		query += " WHERE id = $" + strconv.Itoa(argCount)
		args = append(args, planID)

		result, err := db.Exec(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Plan bulunamadı",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "VIP planı güncellendi",
		})
	}
}

// AdminDeleteVIPPlan API - VIP planı sil
func AdminDeleteVIPPlan(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		planID, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Geçersiz plan ID", http.StatusBadRequest)
			return
		}

		// Önce bu plana ait satın alma var mı kontrol et
		var purchaseCount int
		err = db.QueryRow("SELECT COUNT(*) FROM vip_purchases WHERE plan_id = $1", planID).Scan(&purchaseCount)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if purchaseCount > 0 {
			// Satın alma varsa silme, sadece pasif yap
			_, err = db.Exec("UPDATE vip_plans SET is_active = false WHERE id = $1", planID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Plana ait satın almalar olduğu için plan pasif hale getirildi",
			})
			return
		}

		// Satın alma yoksa direkt sil
		_, err = db.Exec("DELETE FROM vip_plans WHERE id = $1", planID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "VIP planı silindi",
		})
	}
}

// /----------------------------------------------------------------------------------------
// DENEYSEL
// Template fonksiyonlarını tanımla
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"toLower":   strings.ToLower,
		"toUpper":   strings.ToUpper,
		"replace":   strings.ReplaceAll,
		"split":     strings.Split,
		"join":      strings.Join,
		"trim":      strings.TrimSpace,
		"now":       time.Now,
		"formatDate": func(t time.Time) string {
			return t.Format("02.01.2006 15:04")
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b int) int { return a * b },
		"div": func(a, b int) int { return a / b },
		"mod": func(a, b int) int { return a % b },
	}
}

// Güncellenmiş AdminSettingsPage fonksiyonu
func AdminSettingsPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "admin_session")
		username := session.Values["username"].(string)
		role := session.Values["role"].(string)

		// Ayarları getir - struct olarak tanımla
		type Settings struct {
			SiteName             string
			SiteURL              string
			SiteDescription      string
			SiteKeywords         string
			LogoURL              string
			MaintenanceMode      bool
			RegistrationOpen     bool
			DebugMode            bool
			ThemeColor           string
			BackgroundPattern    string
			DefaultLanguage      string
			Timezone             string
			DateFormat           string
			SessionTimeout       int
			MaxSessions          int
			MaxLoginAttempts     int
			LockoutTime          int
			TwoFactorAuth        bool
			RecaptchaEnabled     bool
			LogIPAddress         bool
			ForceHTTPS           bool
			JWTSecret            string
			JWTExpiry            int
			RefreshTokenExpiry   int
			RateLimit            int
			BlockedIPs           string
			BlockedCountries     string
			SMTPHost             string
			SMTPPort             int
			SMTPUsername         string
			SMTPPassword         string
			SMTPFromEmail        string
			SMTPFromName         string
			SMTPSSL              bool
			SMTPEnabled          bool
			DockerHost           string
			DockerAPIVersion     string
			DockerNetwork        string
			MaxContainers        int
			ContainerTimeout     int
			ContainerCPU         float64
			ContainerMemory      int
			ContainerDisk        int
			AutoStartContainers  bool
			ContainerLogging     bool
			MaxUsers             int
			MaxMachines          int
			DailySubmissionLimit int
			MaxFlagAttempts      int
			MaxUploadSize        int
			AllowedFileTypes     string
			MinPoints            int
			MaxPoints            int
			VIPPrice             float64
			VIPDuration          int
			MailSubject          string
			MailBody             string
			BackupCron           string
			MaxBackups           int
			BackupPath           string
			AutoBackup           bool
			BackupDatabase       bool
			BackupFiles          bool
		}

		settings := Settings{
			// Varsayılan değerler
			SiteName:             "CTF Platform",
			SiteURL:              "http://localhost:8181",
			LogoURL:              "/static/images/logo.png",
			ThemeColor:           "#00ff9d",
			DefaultLanguage:      "tr",
			Timezone:             "Europe/Istanbul",
			DateFormat:           "DD.MM.YYYY",
			SessionTimeout:       60,
			MaxSessions:          5,
			MaxLoginAttempts:     5,
			LockoutTime:          15,
			JWTExpiry:            24,
			RefreshTokenExpiry:   7,
			RateLimit:            100,
			SMTPPort:             587,
			MaxContainers:        10,
			ContainerTimeout:     60,
			ContainerCPU:         1.0,
			ContainerMemory:      512,
			ContainerDisk:        10,
			MaxUsers:             10000,
			MaxMachines:          100,
			DailySubmissionLimit: 100,
			MaxFlagAttempts:      5,
			MaxUploadSize:        10,
			AllowedFileTypes:     ".jpg,.png,.pdf,.txt",
			MinPoints:            0,
			MaxPoints:            10000,
			VIPPrice:             99.90,
			VIPDuration:          30,
			MaxBackups:           10,
			BackupPath:           "/backups",
		}

		// Veritabanından ayarları çek
		rows, err := db.Query("SELECT key, value FROM system_settings")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var key, value string
				rows.Scan(&key, &value)

				// String değerler
				switch key {
				case "site_name":
					settings.SiteName = value
				case "site_url":
					settings.SiteURL = value
				case "site_description":
					settings.SiteDescription = value
				case "site_keywords":
					settings.SiteKeywords = value
				case "logo_url":
					settings.LogoURL = value
				case "theme_color":
					settings.ThemeColor = value
				case "background_pattern":
					settings.BackgroundPattern = value
				case "default_language":
					settings.DefaultLanguage = value
				case "timezone":
					settings.Timezone = value
				case "date_format":
					settings.DateFormat = value
				case "jwt_secret":
					settings.JWTSecret = value
				case "blocked_ips":
					settings.BlockedIPs = value
				case "blocked_countries":
					settings.BlockedCountries = value
				case "smtp_host":
					settings.SMTPHost = value
				case "smtp_username":
					settings.SMTPUsername = value
				case "smtp_password":
					settings.SMTPPassword = value
				case "smtp_from_email":
					settings.SMTPFromEmail = value
				case "smtp_from_name":
					settings.SMTPFromName = value
				case "docker_host":
					settings.DockerHost = value
				case "docker_api_version":
					settings.DockerAPIVersion = value
				case "docker_network":
					settings.DockerNetwork = value
				case "allowed_file_types":
					settings.AllowedFileTypes = value
				case "mail_subject":
					settings.MailSubject = value
				case "mail_body":
					settings.MailBody = value
				case "backup_cron":
					settings.BackupCron = value
				case "backup_path":
					settings.BackupPath = value
				}

				// Boolean değerler
				switch key {
				case "maintenance_mode":
					settings.MaintenanceMode = value == "true"
				case "registration_open":
					settings.RegistrationOpen = value == "true"
				case "debug_mode":
					settings.DebugMode = value == "true"
				case "two_factor_auth":
					settings.TwoFactorAuth = value == "true"
				case "recaptcha_enabled":
					settings.RecaptchaEnabled = value == "true"
				case "log_ip_address":
					settings.LogIPAddress = value == "true"
				case "force_https":
					settings.ForceHTTPS = value == "true"
				case "smtp_ssl":
					settings.SMTPSSL = value == "true"
				case "smtp_enabled":
					settings.SMTPEnabled = value == "true"
				case "auto_start_containers":
					settings.AutoStartContainers = value == "true"
				case "container_logging":
					settings.ContainerLogging = value == "true"
				case "auto_backup":
					settings.AutoBackup = value == "true"
				case "backup_database":
					settings.BackupDatabase = value == "true"
				case "backup_files":
					settings.BackupFiles = value == "true"
				}

				// Integer değerler
				intFields := map[string]*int{
					"session_timeout":        &settings.SessionTimeout,
					"max_sessions":           &settings.MaxSessions,
					"max_login_attempts":     &settings.MaxLoginAttempts,
					"lockout_time":           &settings.LockoutTime,
					"jwt_expiry":             &settings.JWTExpiry,
					"refresh_token_expiry":   &settings.RefreshTokenExpiry,
					"rate_limit":             &settings.RateLimit,
					"smtp_port":              &settings.SMTPPort,
					"max_containers":         &settings.MaxContainers,
					"container_timeout":      &settings.ContainerTimeout,
					"container_memory":       &settings.ContainerMemory,
					"container_disk":         &settings.ContainerDisk,
					"max_users":              &settings.MaxUsers,
					"max_machines":           &settings.MaxMachines,
					"daily_submission_limit": &settings.DailySubmissionLimit,
					"max_flag_attempts":      &settings.MaxFlagAttempts,
					"max_upload_size":        &settings.MaxUploadSize,
					"min_points":             &settings.MinPoints,
					"max_points":             &settings.MaxPoints,
					"vip_duration":           &settings.VIPDuration,
					"max_backups":            &settings.MaxBackups,
				}

				for field, ptr := range intFields {
					if key == field {
						if intVal, err := strconv.Atoi(value); err == nil {
							*ptr = intVal
						}
					}
				}

				// Float değerler
				if key == "container_cpu" {
					if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
						settings.ContainerCPU = floatVal
					}
				}
				if key == "vip_price" {
					if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
						settings.VIPPrice = floatVal
					}
				}
			}
		}

		admin := models.Admin{
			Username: username,
			Role:     role,
			Avatar:   "/static/images/avatar.png",
		}

		data := struct {
			Title    string
			Active   string
			Admin    models.Admin
			Settings Settings // interface{} yerine Settings tipi
		}{
			Title:    "Sistem Ayarları - Admin Panel",
			Active:   "settings",
			Admin:    admin,
			Settings: settings,
		}

		// Template fonksiyonlarını tanımla
		funcMap := template.FuncMap{
			"contains": func(s, substr string) bool {
				return strings.Contains(s, substr)
			},
			"eq": func(a, b interface{}) bool {
				return a == b
			},
		}

		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			"templates/admin/layout.html",
			"templates/admin/settings.html",
		)
		if err != nil {
			http.Error(w, "Template yüklenemedi: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template çalıştırılamadı: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// Sistem ayarları struct'ı

// Helper fonksiyonlar
func getSystemSettings(db *sql.DB) (models.SystemSettings, error) {
	var settings models.SystemSettings

	// Veritabanından ayarları çek (örnek)
	rows, err := db.Query("SELECT key, value FROM system_settings")
	if err != nil {
		return settings, err
	}
	defer rows.Close()

	settingsMap := make(map[string]string)
	for rows.Next() {
		var key, value string
		rows.Scan(&key, &value)
		settingsMap[key] = value
	}

	// Map'ten struct'a dönüştür
	settings.SiteName = settingsMap["site_name"]
	settings.SiteDescription = settingsMap["site_description"]
	settings.MaintenanceMode = settingsMap["maintenance_mode"] == "true"
	// ... diğer alanlar

	return settings, nil
}

func getDefaultSettings() models.SystemSettings {
	return models.SystemSettings{
		SiteName:          "HACKLAB CTF Platform",
		SiteDescription:   "Güvenlik uzmanları yetiştiren CTF platformu",
		SiteKeywords:      "ctf, cybersecurity, hacking, pentest",
		MaintenanceMode:   false,
		RegistrationOpen:  true,
		DefaultUserPoints: 100,
		SessionTimeout:    120,
		MaxUploadSize:     10,
		AllowedFileTypes:  []string{".jpg", ".png", ".txt", ".pdf"},
		SecuritySettings: models.SecuritySettings{
			TwoFactorAuth:   false,
			PasswordMinLen:  8,
			PasswordComplex: true,
			LoginAttempts:   5,
			BlockDuration:   30,
		},
		CTFSettings: models.CTFSettings{
			EnableCTF:        true,
			MaxTeamSize:      4,
			EnableScoreboard: true,
			FlagFormat:       "flag{...}",
		},
	}
}
