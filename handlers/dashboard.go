// handlers/dashboard.go
package handlers

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"

	"ctf-platform/models"

	"github.com/gorilla/sessions"
)



func GetMyProfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")

		var user models.User
		err := db.QueryRow(`
            SELECT id, username, email, avatar, bio, location, website,
                   is_vip, points, rank, created_at, last_login
            FROM users
            WHERE id = $1 AND is_active = true
        `, userID).Scan(
			&user.ID, &user.Username, &user.Email, &user.Avatar, &user.Bio,
			&user.Location, &user.Website, &user.IsVIP, &user.Points,
			&user.Rank, &user.CreatedAt, &user.LastLogin,
		)

		if err != nil {
			http.Error(w, "Kullanıcı bulunamadı", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(user)
	}
}

func UpdateProfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")

		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Geçersiz istek", http.StatusBadRequest)
			return
		}

		// Güncellenebilir alanlar
		allowedFields := []string{"bio", "location", "website", "avatar"}

		query := "UPDATE users SET "
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

		query += " WHERE id = $" + strconv.Itoa(argCount)
		args = append(args, userID)

		_, err := db.Exec(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Profil güncellendi",
		})
	}
}

func DashboardPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		isAuth := false
		var user *models.User
		var stats models.DashboardStats
		recentActivity := []models.Activity{}
		inProgress := []models.InProgressMachine{}
		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			isAuth = true
			userID := session.Values["user_id"].(int)

			user = &models.User{}
			db.QueryRow(`
                SELECT id, username, email, avatar, bio, location, website,
                       is_vip, points, rank, created_at
                FROM users WHERE id = $1
            `, userID).Scan(
				&user.ID, &user.Username, &user.Email, &user.Avatar, &user.Bio,
				&user.Location, &user.Website, &user.IsVIP, &user.Points, &user.Rank,
				&user.CreatedAt,
			)

			// İstatistikler
			db.QueryRow(`
                SELECT 
                    COUNT(DISTINCT machine_id) as total_solved,
                    COALESCE(SUM(mq.points_reward), 0) as total_points
                FROM user_solutions us
                JOIN machine_questions mq ON us.question_id = mq.id
                WHERE us.user_id = $1
            `, userID).Scan(&stats.TotalSolved, &stats.TotalPoints)

			db.QueryRow("SELECT COUNT(*) FROM machines WHERE is_active = true").Scan(&stats.TotalMachines)

			// Günlük hedef
			db.QueryRow(`
                SELECT COUNT(*) FROM user_solutions
                WHERE user_id = $1 AND DATE(solved_at) = CURRENT_DATE
            `, userID).Scan(&stats.DailyProgress)
			stats.DailyGoal = 5

			// Seri
			db.QueryRow(`
                WITH days AS (
                    SELECT DISTINCT DATE(solved_at) as day
                    FROM user_solutions
                    WHERE user_id = $1
                    ORDER BY day DESC
                )
                SELECT COUNT(*)
                FROM days
                WHERE day > CURRENT_DATE - INTERVAL '7 days'
            `, userID).Scan(&stats.Streak)

			// VIP makine sayısı
			db.QueryRow(`
                SELECT COUNT(DISTINCT m.id)
                FROM user_solutions us
                JOIN machines m ON us.machine_id = m.id
                WHERE us.user_id = $1 AND m.is_vip_only = true
            `, userID).Scan(&stats.VIPCount)

			// Son aktiviteler
			rows, err := db.Query(`
                SELECT action_type, machine_id, created_at
                FROM activity_logs
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT 10
            `, userID)

			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var a models.Activity
					rows.Scan(&a.Type, &a.MachineID, &a.CreatedAt)
					recentActivity = append(recentActivity, a)
				}
			}

			// Devam eden makineler
			rows, err = db.Query(`
                SELECT m.id, m.name, m.difficulty,
                       COUNT(DISTINCT us.question_id) as solved,
                       COUNT(DISTINCT mq.id) as total
                FROM user_solutions us
                JOIN machines m ON us.machine_id = m.id
                JOIN machine_questions mq ON m.id = mq.machine_id
                WHERE us.user_id = $1
                GROUP BY m.id, m.name, m.difficulty
                HAVING COUNT(DISTINCT us.question_id) < COUNT(DISTINCT mq.id)
                ORDER BY MAX(us.solved_at) DESC
                LIMIT 5
            `, userID)

			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var ip models.InProgressMachine
					rows.Scan(&ip.ID, &ip.Name, &ip.Difficulty, &ip.Solved, &ip.Total)
					inProgress = append(inProgress, ip)
				}
			}
		}

		data := models.DashboardData{
			Title:           "Dashboard - CTF HACK PLATFORMU",
			User:            user,
			IsAuthenticated: isAuth,
			Stats:           stats,
			RecentActivity:  recentActivity,
			InProgress:      inProgress,
		}

		tmpl := template.Must(template.ParseFiles("templates/dashboard.html"))
		tmpl.Execute(w, data)
	}
}
