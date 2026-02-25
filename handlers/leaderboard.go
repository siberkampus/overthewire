// handlers/leaderboard.go
package handlers

import (
    "encoding/json"
    "html/template"
    "net/http"
    "strconv"
    "database/sql"
    
    "ctf-platform/models"
)

type LeaderboardData struct {
    Title          string
    User           *models.User
    IsAuthenticated bool
    Entries        []models.LeaderboardEntry
    Stats          LeaderboardStats
    UserRank       int
}

type LeaderboardStats struct {
    TotalUsers     int
    TotalSolutions int
    TotalPoints    int
}

type LeaderboardFilters struct {
    Timeframe string
    Country   string
    SortBy    string
    Page      int
    Limit     int
}

func GetLeaderboard(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        timeframe := r.URL.Query().Get("timeframe")
        country := r.URL.Query().Get("country")
        sortBy := r.URL.Query().Get("sort")
        page, _ := strconv.Atoi(r.URL.Query().Get("page"))
        limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

        if page < 1 {
            page = 1
        }
        if limit < 1 {
            limit = 50
        }

        query := `
            SELECT 
                u.id,
                u.username,
                u.avatar,
                u.country,
                u.points,
                u.rank,
                u.is_vip,
                COUNT(DISTINCT us.machine_id) as machines_solved,
                COUNT(DISTINCT us.question_id) as questions_solved,
                ROUND(AVG(CASE WHEN us.id IS NOT NULL THEN 100 ELSE 0 END)) as accuracy
            FROM users u
            LEFT JOIN user_solutions us ON u.id = us.user_id
            WHERE u.is_active = true
        `

        var args []interface{}
        argCount := 1

        if country != "" && country != "all" {
            query += ` AND u.country = $` + strconv.Itoa(argCount)
            args = append(args, country)
            argCount++
        }

        if timeframe != "" && timeframe != "all" {
            switch timeframe {
            case "today":
                query += ` AND us.solved_at > NOW() - INTERVAL '1 day'`
            case "week":
                query += ` AND us.solved_at > NOW() - INTERVAL '7 days'`
            case "month":
                query += ` AND us.solved_at > NOW() - INTERVAL '30 days'`
            case "year":
                query += ` AND us.solved_at > NOW() - INTERVAL '1 year'`
            }
        }

        query += ` GROUP BY u.id`

        switch sortBy {
        case "points":
            query += ` ORDER BY u.points DESC`
        case "solved":
            query += ` ORDER BY machines_solved DESC`
        case "accuracy":
            query += ` ORDER BY accuracy DESC`
        default:
            query += ` ORDER BY u.points DESC`
        }

        query += ` LIMIT $` + strconv.Itoa(argCount) + ` OFFSET $` + strconv.Itoa(argCount+1)
        args = append(args, limit, (page-1)*limit)

        rows, err := db.Query(query, args...)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        var entries []models.LeaderboardEntry
        for rows.Next() {
            var e models.LeaderboardEntry
            rows.Scan(
                &e.ID, &e.Username, &e.Avatar, &e.Country,
                &e.Points, &e.Rank, &e.IsVIP,
                &e.MachinesSolved, &e.QuestionsSolved, &e.Accuracy,
            )
            entries = append(entries, e)
        }

        // Toplam kullanıcı sayısı
        var totalUsers int
        db.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = true").Scan(&totalUsers)

        // Toplam çözüm sayısı
        var totalSolutions int
        db.QueryRow("SELECT COUNT(*) FROM user_solutions").Scan(&totalSolutions)

        // Toplam puan
        var totalPoints int
        db.QueryRow("SELECT COALESCE(SUM(points), 0) FROM users").Scan(&totalPoints)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "entries":      entries,
            "total":        totalUsers,
            "page":         page,
            "limit":        limit,
            "total_pages":  (totalUsers + limit - 1) / limit,
            "stats": map[string]interface{}{
                "total_users":     totalUsers,
                "total_solutions": totalSolutions,
                "total_points":    totalPoints,
            },
        })
    }
}

func LeaderboardPage(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // İlk 100 kullanıcıyı getir
        rows, err := db.Query(`
            SELECT 
                u.id,
                u.username,
                u.avatar,
                u.country,
                u.points,
                u.rank,
                u.is_vip,
                COUNT(DISTINCT us.machine_id) as machines_solved,
                ROUND(AVG(CASE WHEN us.id IS NOT NULL THEN 100 ELSE 0 END)) as accuracy
            FROM users u
            LEFT JOIN user_solutions us ON u.id = us.user_id
            WHERE u.is_active = true
            GROUP BY u.id
            ORDER BY u.points DESC
            LIMIT 100
        `)

        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        var entries []models.LeaderboardEntry
        for rows.Next() {
            var e models.LeaderboardEntry
            rows.Scan(
                &e.ID, &e.Username, &e.Avatar, &e.Country,
                &e.Points, &e.Rank, &e.IsVIP,
                &e.MachinesSolved, &e.Accuracy,
            )
            entries = append(entries, e)
        }

        // İstatistikler
        var stats LeaderboardStats
        db.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = true").Scan(&stats.TotalUsers)
        db.QueryRow("SELECT COUNT(*) FROM user_solutions").Scan(&stats.TotalSolutions)
        db.QueryRow("SELECT COALESCE(SUM(points), 0) FROM users").Scan(&stats.TotalPoints)

        data := LeaderboardData{
            Title:          "Liderlik Tablosu - CTF HACK PLATFORMU",
            Entries:        entries,
            Stats:          stats,
        }

        tmpl := template.Must(template.ParseFiles("templates/leaderboard.html"))
        tmpl.Execute(w, data)
    }
}