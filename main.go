package main

import (
	"log"
	"net/http"
	"time"

	"ctf-platform/database"
	"ctf-platform/handlers"
	"ctf-platform/middleware"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	store = sessions.NewCookieStore([]byte("super-secret-key"))
)

func main() {
	// Veritabanı bağlantısı
	db, err := database.Connect()
	if err != nil {
		log.Fatal("Veritabanı bağlantı hatası:", err)
	}
	defer db.Close()

	// Router oluştur
	r := mux.NewRouter()
	r.Use(middleware.Logger)

	// Statik dosyalar
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// API Router
	api := r.PathPrefix("/api").Subrouter()
	api.Use(middleware.Logger)
	// api.Use(middleware.CORS)

	// Public API endpoints
	api.HandleFunc("/auth/login", handlers.Login(db, store)).Methods("POST", "OPTIONS")
	api.HandleFunc("/auth/register", handlers.Register(db)).Methods("POST", "OPTIONS")
	api.HandleFunc("/auth/logout", handlers.Logout(store)).Methods("POST", "OPTIONS")
	api.HandleFunc("/auth/refresh", handlers.RefreshToken(db)).Methods("POST", "OPTIONS")

	// Public endpoints
	api.HandleFunc("/machines", handlers.GetMachines(db)).Methods("GET")
	api.HandleFunc("/machines/{id}", handlers.GetMachineDetail(db)).Methods("GET")
	api.HandleFunc("/leaderboard", handlers.GetLeaderboard(db)).Methods("GET")
	api.HandleFunc("/profile/{username}", handlers.GetPublicProfile(db)).Methods("GET")

	// Protected API endpoints
	protected := api.PathPrefix("/").Subrouter()
	protected.Use(middleware.Auth(store))

	protected.HandleFunc("/user/profile", handlers.GetMyProfile(db)).Methods("GET")
	protected.HandleFunc("/user/profile", handlers.UpdateProfile(db)).Methods("PUT")
	protected.HandleFunc("/user/settings", handlers.GetSettings(db)).Methods("GET")
	protected.HandleFunc("/user/settings", handlers.UpdateSettings(db)).Methods("PUT")
	protected.HandleFunc("/user/security", handlers.UpdateSecurity(db)).Methods("PUT")
	protected.HandleFunc("/user/avatar", handlers.UploadAvatar(db)).Methods("POST")

	protected.HandleFunc("/machines/{id}/start", handlers.StartMachine(db)).Methods("POST")
	protected.HandleFunc("/machines/{id}/stop", handlers.StopMachine(db)).Methods("POST")
	protected.HandleFunc("/machines/{id}/submit", handlers.SubmitFlag(db)).Methods("POST")
	protected.HandleFunc("/machines/{id}/hint/{questionId}", handlers.GetHint(db)).Methods("GET")

	protected.HandleFunc("/vip/purchase", handlers.PurchaseVIP(db)).Methods("POST")
	protected.HandleFunc("/vip/status", handlers.GetVIPStatus(db)).Methods("GET")

	protected.HandleFunc("/sessions", handlers.GetSessions(db, store)).Methods("GET")
	protected.HandleFunc("/sessions/{id}", handlers.TerminateSession(db, store)).Methods("DELETE")
	protected.HandleFunc("/sessions/terminate-all", handlers.TerminateAllSessions(db, store)).Methods("POST")

	// WebSocket for terminal
	protected.HandleFunc("/ws/terminal/{sessionId}", handlers.TerminalWebSocket(db, store))

	// Page routes (HTML templates)
	r.HandleFunc("/", handlers.HomePage(db, store)).Methods("GET")
	r.HandleFunc("/login", handlers.LoginPage(store)).Methods("GET")
	r.HandleFunc("/register", handlers.RegisterPage()).Methods("GET")
	r.HandleFunc("/machines", handlers.MachinesPage(db, store)).Methods("GET")
	r.HandleFunc("/machines/{id}", handlers.MachineDetailPage(db, store)).Methods("GET")
	r.HandleFunc("/machines/{id}/terminal", handlers.TerminalPage(db, store)).Methods("GET")
	r.HandleFunc("/leaderboard", handlers.LeaderboardPage(db)).Methods("GET")
	r.HandleFunc("/profile/{username}", handlers.ProfilePage(db)).Methods("GET")
	r.HandleFunc("/dashboard", handlers.DashboardPage(db, store)).Methods("GET")
	r.HandleFunc("/vip", handlers.VIPPage(db, store)).Methods("GET")
	r.HandleFunc("/settings", handlers.SettingsPage(db, store)).Methods("GET")

	// Admin paneli
	admin := r.PathPrefix("/admin").Subrouter()

	// Public admin routes
	admin.HandleFunc("/login", handlers.AdminLoginPage).Methods("GET")
	admin.HandleFunc("/login", handlers.AdminLogin(db, store)).Methods("POST")

	// Protected admin routes
	adminProtected := admin.PathPrefix("/").Subrouter()
	adminProtected.Use(middleware.AdminAuth(store))

	// ============ ADMIN HTML SAYFALARI (GÖRÜNÜM) ============
	adminProtected.HandleFunc("/dashboard", handlers.AdminDashboard(db, store)).Methods("GET")
	adminProtected.HandleFunc("/users", handlers.AdminUsersPage(db, store)).Methods("GET")              // users.html
	adminProtected.HandleFunc("/users/add", handlers.AdminAddUserForm(db, store)).Methods("GET")        // user_form.html (yeni)
	adminProtected.HandleFunc("/users/edit/{id}", handlers.AdminEditUserForm(db, store)).Methods("GET") // user_form.html (düzenle)
	adminProtected.HandleFunc("/machines", handlers.AdminMachinesPage(db, store)).Methods("GET")        // machines.html
	adminProtected.HandleFunc("/machines/add", handlers.AdminAddMachineForm(db, store)).Methods("GET")  // machine_form.html
	adminProtected.HandleFunc("/machines/edit/{id}", handlers.AdminEditMachineForm(db)).Methods("GET")  // machine_form.html
	adminProtected.HandleFunc("/questions", handlers.AdminQuestionsPage(db, store)).Methods("GET")      // questions.html
	adminProtected.HandleFunc("/vip", handlers.AdminVIPPage(db, store)).Methods("GET")                  // vip.html
	adminProtected.HandleFunc("/stats", handlers.AdminStatsPage(db, store)).Methods("GET")              // stats.html
	adminProtected.HandleFunc("/logs", handlers.AdminLogsPage(db, store)).Methods("GET")                // logs.html
	adminProtected.HandleFunc("/settings", handlers.AdminSettingsPage(db, store)).Methods("GET")        // settings.html
	adminProtected.HandleFunc("/submissions", handlers.AdminSubmissionsPage(db, store)).Methods("GET")  // submissions.html

	// ============ ADMIN API ENDPOINT'LERİ (JSON) ============
	adminAPI := adminProtected.PathPrefix("/api").Subrouter()

	// User API
	adminAPI.HandleFunc("/users", handlers.AdminUsers(db, store)).Methods("GET")
	adminAPI.HandleFunc("/users/{id}", handlers.AdminUserDetail(db)).Methods("GET")
	adminAPI.HandleFunc("/users/{id}", handlers.AdminUpdateUser(db)).Methods("PUT")
	adminAPI.HandleFunc("/users/{id}/toggle-status", handlers.AdminToggleUserStatus(db)).Methods("POST")
	adminAPI.HandleFunc("/users/{id}/toggle-vip", handlers.AdminToggleUserVIP(db)).Methods("POST")
	adminAPI.HandleFunc("/users/{id}/reset-password", handlers.AdminResetPassword(db)).Methods("POST")
	adminAPI.HandleFunc("/users/{id}", handlers.AdminDeleteUser(db)).Methods("DELETE")
	adminAPI.HandleFunc("/users/create", handlers.AdminCreateUser(db)).Methods("POST")

	// Machine API
	adminAPI.HandleFunc("/machines", handlers.AdminMachines(db)).Methods("GET")
	adminAPI.HandleFunc("/machines", handlers.AdminCreateMachine(db, store)).Methods("POST")
	adminAPI.HandleFunc("/machines/{id}", handlers.AdminUpdateMachine(db)).Methods("PUT")
	adminAPI.HandleFunc("/machines/{id}/toggle", handlers.AdminToggleMachine(db)).Methods("POST")
	adminAPI.HandleFunc("/machines/{id}", handlers.AdminDeleteMachine(db)).Methods("DELETE")

	// Question API
	adminAPI.HandleFunc("/questions", handlers.AdminQuestions(db)).Methods("GET")
	adminAPI.HandleFunc("/questions", handlers.AdminCreateQuestion(db)).Methods("POST")
	adminAPI.HandleFunc("/questions/{id}", handlers.AdminUpdateQuestion(db, store)).Methods("PUT")
	adminAPI.HandleFunc("/questions/{id}/toggle", handlers.AdminToggleQuestion(db)).Methods("POST")
	adminAPI.HandleFunc("/questions/{id}", handlers.AdminDeleteQuestion(db)).Methods("DELETE")

	// VIP API
	adminAPI.HandleFunc("/vip", handlers.AdminVIPManagement(db)).Methods("GET")
	adminAPI.HandleFunc("/vip/plans", handlers.AdminVIPPlans(db)).Methods("GET")
	adminAPI.HandleFunc("/vip/plans", handlers.AdminCreateVIPPlan(db)).Methods("POST")
	adminAPI.HandleFunc("/vip/plans/{id}", handlers.AdminUpdateVIPPlan(db)).Methods("PUT")
	adminAPI.HandleFunc("/vip/plans/{id}", handlers.AdminDeleteVIPPlan(db)).Methods("DELETE")
	adminAPI.HandleFunc("/vip/purchases", handlers.AdminVIPPurchases(db)).Methods("GET")

	// Stats API
	adminAPI.HandleFunc("/stats", handlers.AdminSystemStats(db)).Methods("GET")
	adminAPI.HandleFunc("/stats/daily", handlers.AdminDailyStats(db)).Methods("GET")
	adminAPI.HandleFunc("/stats/charts", handlers.AdminChartData(db)).Methods("GET")

	// Logs API
	adminAPI.HandleFunc("/logs", handlers.AdminLogs(db)).Methods("GET")
	adminAPI.HandleFunc("/logs/export", handlers.AdminExportLogs(db)).Methods("GET")

	// Settings API
	adminAPI.HandleFunc("/settings", handlers.AdminSettings(db)).Methods("GET")
	adminAPI.HandleFunc("/settings", handlers.AdminUpdateSettings(db)).Methods("POST")

	// Admin logout
	adminAPI.HandleFunc("/logout", handlers.AdminLogout(store)).Methods("POST")

	// CORS ayarları (gerekirse aç)
	// c := cors.New(cors.Options{
	// 	AllowedOrigins:   []string{"http://localhost:8080"},
	// 	AllowCredentials: true,
	// 	AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	// 	AllowedHeaders:   []string{"Content-Type", "Authorization"},
	// })
	// handler := c.Handler(r)

	handler := r

	// Sunucuyu başlat
	srv := &http.Server{
		Handler:      handler,
		Addr:         ":8181",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Sunucu başlatılıyor: http://localhost:8181")
	log.Println("Admin panel: http://localhost:8181/admin/login")
	log.Fatal(srv.ListenAndServe())
}
