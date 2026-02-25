// handlers/profile.go
package handlers

import (
    "encoding/json"
    "html/template"
    "net/http"
    "database/sql"
    
    "ctf-platform/models"
    
    "github.com/gorilla/mux"
)

type ProfileData struct {
    Title          string
    User           *models.User
    IsAuthenticated bool
    ProfileUser    *models.User
    IsOwnProfile   bool
    Stats          ProfileStats
    SolvedMachines []models.SolvedMachine
    Badges         []models.Badge
    Activity       []models.Activity
    Followers      []models.Follower
    Following      int
    IsFollowing    bool
}

type ProfileStats struct {
    TotalPoints     int
    TotalMachines   int
    TotalQuestions  int
    Accuracy        int
    Rank            int
    VIPCount        int
    FirstBloods     int
}

func GetPublicProfile(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        username := vars["username"]

        var user models.User
        err := db.QueryRow(`
            SELECT id, username, email, avatar, bio, location, website,
                   is_vip, points, rank, created_at, last_login
            FROM users
            WHERE username = $1 AND is_active = true
        `, username).Scan(
            &user.ID, &user.Username, &user.Email, &user.Avatar, &user.Bio,
            &user.Location, &user.Website, &user.IsVIP, &user.Points,
            &user.Rank, &user.CreatedAt, &user.LastLogin,
        )

        if err != nil {
            http.Error(w, "Kullanıcı bulunamadı", http.StatusNotFound)
            return
        }

        // İstatistikler
        var stats ProfileStats
        db.QueryRow(`
            SELECT 
                COUNT(DISTINCT machine_id) as total_machines,
                COUNT(*) as total_questions,
                COALESCE(ROUND(AVG(CASE WHEN used_hint THEN 80 ELSE 100 END)), 0) as accuracy,
                COUNT(CASE WHEN used_hint = false THEN 1 END) as first_bloods
            FROM user_solutions
            WHERE user_id = $1
        `, user.ID).Scan(&stats.TotalMachines, &stats.TotalQuestions, &stats.Accuracy, &stats.FirstBloods)

        stats.TotalPoints = user.Points
        stats.Rank = user.Rank

        // VIP makine sayısı
        db.QueryRow(`
            SELECT COUNT(DISTINCT m.id)
            FROM user_solutions us
            JOIN machines m ON us.machine_id = m.id
            WHERE us.user_id = $1 AND m.is_vip_only = true
        `, user.ID).Scan(&stats.VIPCount)

        // Çözülen makineler
        rows, err := db.Query(`
            SELECT DISTINCT m.id, m.name, m.difficulty, m.points_reward,
                   MAX(us.solved_at) as solved_at
            FROM user_solutions us
            JOIN machines m ON us.machine_id = m.id
            WHERE us.user_id = $1
            GROUP BY m.id, m.name, m.difficulty, m.points_reward
            ORDER BY solved_at DESC
            LIMIT 20
        `, user.ID)

        var solvedMachines []models.SolvedMachine
        if err == nil {
            defer rows.Close()
            for rows.Next() {
                var sm models.SolvedMachine
                rows.Scan(&sm.ID, &sm.Name, &sm.Difficulty, &sm.Points, &sm.SolvedAt)
                solvedMachines = append(solvedMachines, sm)
            }
        }

        // Rozetler
        rows, err = db.Query(`
            SELECT a.id, a.name, a.description, a.icon, ua.earned_at
            FROM user_achievements ua
            JOIN achievements a ON ua.achievement_id = a.id
            WHERE ua.user_id = $1
            ORDER BY ua.earned_at DESC
        `, user.ID)

        var badges []models.Badge
        if err == nil {
            defer rows.Close()
            for rows.Next() {
                var b models.Badge
                rows.Scan(&b.ID, &b.Name, &b.Description, &b.Icon, &b.EarnedAt)
                badges = append(badges, b)
            }
        }

        // Son aktiviteler
        rows, err = db.Query(`
            SELECT action_type, machine_id, question_id, created_at
            FROM activity_logs
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 20
        `, user.ID)

        var activities []models.Activity
        if err == nil {
            defer rows.Close()
            for rows.Next() {
                var a models.Activity
                rows.Scan(&a.Type, &a.MachineID, &a.QuestionID, &a.CreatedAt)
                activities = append(activities, a)
            }
        }

        // Takipçiler
        rows, err = db.Query(`
            SELECT u.id, u.username, u.avatar
            FROM followers f
            JOIN users u ON f.follower_id = u.id
            WHERE f.following_id = $1
            ORDER BY f.created_at DESC
            LIMIT 12
        `, user.ID)

        var followers []models.Follower
        if err == nil {
            defer rows.Close()
            for rows.Next() {
                var f models.Follower
                rows.Scan(&f.ID, &f.Username, &f.Avatar)
                followers = append(followers, f)
            }
        }

        // Takip edilen sayısı
        var following int
        db.QueryRow("SELECT COUNT(*) FROM followers WHERE follower_id = $1", user.ID).Scan(&following)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "user":           user,
            "stats":          stats,
            "solved_machines": solvedMachines,
            "badges":         badges,
            "activity":       activities,
            "followers":      followers,
            "following":      following,
        })
    }
}

func ProfilePage(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        username := vars["username"]

        var profileUser models.User
        err := db.QueryRow(`
            SELECT id, username, email, avatar, bio, location, website,
                   is_vip, points, rank, created_at, last_login
            FROM users
            WHERE username = $1 AND is_active = true
        `, username).Scan(
            &profileUser.ID, &profileUser.Username, &profileUser.Email, &profileUser.Avatar, &profileUser.Bio,
            &profileUser.Location, &profileUser.Website, &profileUser.IsVIP, &profileUser.Points,
            &profileUser.Rank, &profileUser.CreatedAt, &profileUser.LastLogin,
        )

        if err != nil {
            http.Error(w, "Kullanıcı bulunamadı", http.StatusNotFound)
            return
        }

        // İstatistikler
        var stats ProfileStats
        db.QueryRow(`
            SELECT 
                COUNT(DISTINCT machine_id) as total_machines,
                COUNT(*) as total_questions,
                COALESCE(ROUND(AVG(CASE WHEN used_hint THEN 80 ELSE 100 END)), 0) as accuracy,
                COUNT(CASE WHEN used_hint = false THEN 1 END) as first_bloods
            FROM user_solutions
            WHERE user_id = $1
        `, profileUser.ID).Scan(&stats.TotalMachines, &stats.TotalQuestions, &stats.Accuracy, &stats.FirstBloods)

        stats.TotalPoints = profileUser.Points
        stats.Rank = profileUser.Rank

        // VIP makine sayısı
        db.QueryRow(`
            SELECT COUNT(DISTINCT m.id)
            FROM user_solutions us
            JOIN machines m ON us.machine_id = m.id
            WHERE us.user_id = $1 AND m.is_vip_only = true
        `, profileUser.ID).Scan(&stats.VIPCount)

        // Çözülen makineler
        rows, err := db.Query(`
            SELECT DISTINCT m.id, m.name, m.difficulty, m.points_reward,
                   MAX(us.solved_at) as solved_at
            FROM user_solutions us
            JOIN machines m ON us.machine_id = m.id
            WHERE us.user_id = $1
            GROUP BY m.id, m.name, m.difficulty, m.points_reward
            ORDER BY solved_at DESC
            LIMIT 20
        `, profileUser.ID)

        var solvedMachines []models.SolvedMachine
        if err == nil {
            defer rows.Close()
            for rows.Next() {
                var sm models.SolvedMachine
                rows.Scan(&sm.ID, &sm.Name, &sm.Difficulty, &sm.Points, &sm.SolvedAt)
                solvedMachines = append(solvedMachines, sm)
            }
        }

        // Rozetler
        rows, err = db.Query(`
            SELECT a.id, a.name, a.description, a.icon, ua.earned_at
            FROM user_achievements ua
            JOIN achievements a ON ua.achievement_id = a.id
            WHERE ua.user_id = $1
            ORDER BY ua.earned_at DESC
        `, profileUser.ID)

        var badges []models.Badge
        if err == nil {
            defer rows.Close()
            for rows.Next() {
                var b models.Badge
                rows.Scan(&b.ID, &b.Name, &b.Description, &b.Icon, &b.EarnedAt)
                badges = append(badges, b)
            }
        }

        data := ProfileData{
            Title:          profileUser.Username + " - Kullanıcı Profili",
            ProfileUser:    &profileUser,
            Stats:          stats,
            SolvedMachines: solvedMachines,
            Badges:         badges,
        }

        tmpl := template.Must(template.ParseFiles("templates/profile.html"))
        tmpl.Execute(w, data)
    }
}