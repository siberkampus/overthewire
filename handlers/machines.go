// handlers/machines.go
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

type MachinesPageData struct {
	Title           string
	User            *models.User
	IsAuthenticated bool
	Machines        []models.Machine
	TotalCount      int
	UserStats       UserStats
}

type UserStats struct {
	SolvedCount int
	TotalPoints int
	Rank        int
}

type MachineFilter struct {
	Difficulty string
	Status     string
	Access     string
	Search     string
	Sort       string
	Page       int
	Limit      int
}

func GetMachines(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Query parametrelerini al
		difficulty := r.URL.Query().Get("difficulty")
		//status := r.URL.Query().Get("status")
		access := r.URL.Query().Get("access")
		search := r.URL.Query().Get("search")
		sort := r.URL.Query().Get("sort")
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 12
		}

		// SQL sorgusu oluştur
		query := `
            SELECT m.id, m.name, m.description, m.difficulty, 
                   m.points_reward, m.is_vip_only,
                   COUNT(DISTINCT us.user_id) as solver_count,
                   COUNT(DISTINCT mq.id) as total_questions
            FROM machines m
            LEFT JOIN machine_questions mq ON m.id = mq.machine_id
            LEFT JOIN user_solutions us ON m.id = us.machine_id
            WHERE m.is_active = true
        `

		var args []interface{}
		argCount := 1

		if difficulty != "" && difficulty != "all" {
			query += ` AND m.difficulty = $` + strconv.Itoa(argCount)
			args = append(args, difficulty)
			argCount++
		}

		if access == "vip" {
			query += ` AND m.is_vip_only = true`
		} else if access == "free" {
			query += ` AND m.is_vip_only = false`
		}

		if search != "" {
			query += ` AND m.name ILIKE $` + strconv.Itoa(argCount)
			args = append(args, "%"+search+"%")
			argCount++
		}

		query += ` GROUP BY m.id`

		// Sıralama
		switch sort {
		case "newest":
			query += ` ORDER BY m.created_at DESC`
		case "oldest":
			query += ` ORDER BY m.created_at ASC`
		case "most-solved":
			query += ` ORDER BY solver_count DESC`
		case "least-solved":
			query += ` ORDER BY solver_count ASC`
		default:
			query += ` ORDER BY m.created_at DESC`
		}

		// Sayfalama
		query += ` LIMIT $` + strconv.Itoa(argCount) + ` OFFSET $` + strconv.Itoa(argCount+1)
		args = append(args, limit, (page-1)*limit)

		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var machines []models.Machine
		for rows.Next() {
			var m models.Machine
			rows.Scan(&m.ID, &m.Name, &m.Description, &m.Difficulty,
				&m.PointsReward, &m.IsVIPOnly, &m.SolverCount, &m.TotalQuestions)
			machines = append(machines, m)
		}

		// Toplam sayıyı al
		var totalCount int
		db.QueryRow("SELECT COUNT(*) FROM machines WHERE is_active = true").Scan(&totalCount)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"machines":    machines,
			"total":       totalCount,
			"page":        page,
			"limit":       limit,
			"total_pages": (totalCount + limit - 1) / limit,
		})
	}
}

func MachinesPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		isAuth := false
		var user *models.User
		var userStats UserStats

		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			isAuth = true
			userID := session.Values["user_id"].(int)

			user = &models.User{}
			db.QueryRow(`
                SELECT id, username, email, is_vip, points 
                FROM users WHERE id = $1
            `, userID).Scan(&user.ID, &user.Username, &user.Email, &user.IsVIP, &user.Points)

			// Kullanıcı istatistikleri
			db.QueryRow(`
                SELECT COUNT(DISTINCT machine_id), COALESCE(SUM(points), 0)
                FROM user_solutions us
                JOIN machine_questions mq ON us.question_id = mq.id
                WHERE us.user_id = $1
            `, userID).Scan(&userStats.SolvedCount, &userStats.TotalPoints)

			db.QueryRow(`
                SELECT COUNT(*) + 1 FROM users 
                WHERE points > (SELECT points FROM users WHERE id = $1)
            `, userID).Scan(&userStats.Rank)
		}

		data := MachinesPageData{
			Title:           "Makineler - CTF HACK PLATFORMU",
			User:            user,
			IsAuthenticated: isAuth,
			UserStats:       userStats,
		}

		tmpl := template.Must(template.ParseFiles("templates/machines.html"))
		tmpl.Execute(w, data)
	}
}
