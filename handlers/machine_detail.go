// handlers/machine_detail.go
package handlers

import (
    "encoding/json"
    "html/template"
    "net/http"
    "database/sql"
    "time"
    
    "ctf-platform/models"
    
    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}

type MachineDetailData struct {
    Title          string
    User           *models.User
    IsAuthenticated bool
    Machine        models.Machine
    Questions      []models.Question
    RecentSolvers  []models.Solver
    UserProgress   models.UserProgress
    IsVIP          bool
    TimeRemaining  int
}

type FlagSubmitRequest struct {
    QuestionID int    `json:"question_id"`
    Flag       string `json:"flag"`
}

type HintRequest struct {
    QuestionID int `json:"question_id"`
}

func GetMachineDetail(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        machineID := vars["id"]

        var machine models.Machine
        err := db.QueryRow(`
            SELECT m.id, m.name, m.description, m.difficulty, 
                   m.points_reward, m.is_vip_only, m.docker_image,
                   u.username as creator_name,
                   COUNT(DISTINCT us.user_id) as solver_count
            FROM machines m
            JOIN users u ON m.creator_id = u.id
            LEFT JOIN user_solutions us ON m.id = us.machine_id
            WHERE m.id = $1 AND m.is_active = true
            GROUP BY m.id, u.username
        `, machineID).Scan(
            &machine.ID, &machine.Name, &machine.Description, &machine.Difficulty,
            &machine.PointsReward, &machine.IsVIPOnly, &machine.DockerImage,
            &machine.Creator, &machine.SolverCount,
        )

        if err != nil {
            http.Error(w, "Makine bulunamadı", http.StatusNotFound)
            return
        }

        // Soruları getir
        rows, err := db.Query(`
            SELECT id, title, description, points_reward, hint, hint_cost, is_active
            FROM machine_questions
            WHERE machine_id = $1 AND is_active = true
            ORDER BY question_order
        `, machineID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        var questions []models.Question
        for rows.Next() {
            var q models.Question
            rows.Scan(&q.ID, &q.Title, &q.Description, &q.PointsReward, &q.Hint, &q.HintCost, &q.IsActive)
            questions = append(questions, q)
        }

        machine.Questions = questions

        json.NewEncoder(w).Encode(machine)
    }
}

func MachineDetailPage(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        machineID := vars["id"]

        session, _ := store.Get(r, "session")
        isAuth := false
        var user *models.User
        var userProgress models.UserProgress

        if auth, ok := session.Values["authenticated"].(bool); ok && auth {
            isAuth = true
            userID := session.Values["user_id"].(int)
            
            user = &models.User{}
            db.QueryRow(`
                SELECT id, username, email, is_vip, points 
                FROM users WHERE id = $1
            `, userID).Scan(&user.ID, &user.Username, &user.Email, &user.IsVIP, &user.Points)

            // Kullanıcının bu makinedeki ilerlemesi
            db.QueryRow(`
                SELECT COUNT(DISTINCT question_id)
                FROM user_solutions
                WHERE user_id = $1 AND machine_id = $2
            `, userID, machineID).Scan(&userProgress.SolvedQuestions)
        }

        // Makine bilgilerini getir
        var machine models.Machine
        db.QueryRow(`
            SELECT m.id, m.name, m.description, m.difficulty, 
                   m.points_reward, m.is_vip_only, m.docker_image,
                   u.username as creator_name,
                   COUNT(DISTINCT us.user_id) as solver_count
            FROM machines m
            JOIN users u ON m.creator_id = u.id
            LEFT JOIN user_solutions us ON m.id = us.machine_id
            WHERE m.id = $1 AND m.is_active = true
            GROUP BY m.id, u.username
        `, machineID).Scan(
            &machine.ID, &machine.Name, &machine.Description, &machine.Difficulty,
            &machine.PointsReward, &machine.IsVIPOnly, &machine.DockerImage,
            &machine.Creator, &machine.SolverCount,
        )

        // Soruları getir
        rows, err := db.Query(`
            SELECT id, title, description, points_reward, hint, hint_cost, is_active
            FROM machine_questions
            WHERE machine_id = $1 AND is_active = true
            ORDER BY question_order
        `, machineID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        var questions []models.Question
        for rows.Next() {
            var q models.Question
            var solved bool
            
            if isAuth {
                db.QueryRow(`
                    SELECT EXISTS(
                        SELECT 1 FROM user_solutions 
                        WHERE user_id = $1 AND question_id = $2
                    )
                `, user.ID, q.ID).Scan(&solved)
            }
            
            rows.Scan(&q.ID, &q.Title, &q.Description, &q.PointsReward, &q.Hint, &q.HintCost, &q.IsActive)
            q.Solved = solved
            questions = append(questions, q)
        }

        // Son çözenleri getir
        rows, err = db.Query(`
            SELECT u.username, u.avatar, us.solved_at
            FROM user_solutions us
            JOIN users u ON us.user_id = u.id
            WHERE us.machine_id = $1
            ORDER BY us.solved_at DESC
            LIMIT 10
        `, machineID)
        
        var recentSolvers []models.Solver
        if err == nil {
            defer rows.Close()
            for rows.Next() {
                var s models.Solver
                rows.Scan(&s.Username, &s.Avatar, &s.SolvedAt)
                recentSolvers = append(recentSolvers, s)
            }
        }

        data := MachineDetailData{
            Title:           machine.Name + " - CTF HACK PLATFORMU",
            User:            user,
            IsAuthenticated: isAuth,
            Machine:         machine,
            Questions:       questions,
            RecentSolvers:   recentSolvers,
            UserProgress:    userProgress,
            IsVIP:           user != nil && user.IsVIP,
            TimeRemaining:   7200, // 2 saat varsayılan
        }

        tmpl := template.Must(template.ParseFiles("templates/machine_detail.html"))
        tmpl.Execute(w, data)
    }
}

func StartMachine(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        machineID := vars["id"]
        userID := r.Header.Get("X-User-ID")

        // Makine kontrolü
        var isVIPOnly bool
        var dockerImage string
        db.QueryRow("SELECT is_vip_only, docker_image FROM machines WHERE id = $1", machineID).Scan(&isVIPOnly, &dockerImage)

        if isVIPOnly {
            var isVIP bool
            db.QueryRow("SELECT is_vip FROM users WHERE id = $1", userID).Scan(&isVIP)
            if !isVIP {
                http.Error(w, "Bu makine VIP üyelik gerektiriyor", http.StatusForbidden)
                return
            }
        }

        // Docker container başlat (mock)
        containerID := "container_" + userID + "_" + machineID + "_" + time.Now().Format("20060102150405")

        // Session oluştur
        _, err := db.Exec(`
            INSERT INTO machine_sessions (user_id, machine_id, container_id, started_at, expires_at)
            VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '2 hours')
        `, userID, machineID, containerID)

        if err != nil {
            http.Error(w, "Container başlatılamadı", http.StatusInternalServerError)
            return
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":      true,
            "container_id": containerID,
            "message":      "Makine başlatıldı",
        })
    }
}

func StopMachine(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        machineID := vars["id"]
        userID := r.Header.Get("X-User-ID")

        // Container'ı durdur
        db.Exec(`
            UPDATE machine_sessions 
            SET ended_at = NOW() 
            WHERE user_id = $1 AND machine_id = $2 AND ended_at IS NULL
        `, userID, machineID)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Makine durduruldu",
        })
    }
}

func SubmitFlag(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        machineID := vars["id"]
        userID := r.Header.Get("X-User-ID")

        var req FlagSubmitRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Geçersiz istek", http.StatusBadRequest)
            return
        }

        // Flag kontrolü
        var correctFlag string
        var points int
        err := db.QueryRow(`
            SELECT flag_hash, points_reward 
            FROM machine_questions 
            WHERE id = $1 AND machine_id = $2
        `, req.QuestionID, machineID).Scan(&correctFlag, &points)

        if err != nil {
            http.Error(w, "Soru bulunamadı", http.StatusNotFound)
            return
        }

        // Daha önce çözülmüş mü kontrol et
        var solved bool
        db.QueryRow(`
            SELECT EXISTS(
                SELECT 1 FROM user_solutions 
                WHERE user_id = $1 AND question_id = $2
            )
        `, userID, req.QuestionID).Scan(&solved)

        if solved {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Bu soruyu zaten çözdünüz!",
            })
            return
        }

        // Flag karşılaştır (gerçek uygulamada hash karşılaştırması)
        if req.Flag == correctFlag {
            // Çözümü kaydet
            tx, err := db.Begin()
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            _, err = tx.Exec(`
                INSERT INTO user_solutions (user_id, machine_id, question_id, solved_at)
                VALUES ($1, $2, $3, NOW())
            `, userID, machineID, req.QuestionID)

            if err != nil {
                tx.Rollback()
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            // Kullanıcının puanını güncelle
            _, err = tx.Exec(`
                UPDATE users SET points = points + $1 WHERE id = $2
            `, points, userID)

            if err != nil {
                tx.Rollback()
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            tx.Commit()

            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": true,
                "message": "Tebrikler! Doğru flag!",
                "points":  points,
            })
        } else {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Yanlış flag! Tekrar dene.",
            })
        }
    }
}

func GetHint(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        machineID := vars["id"]
        questionID := vars["questionId"]
        userID := r.Header.Get("X-User-ID")

        // İpucu bilgilerini al
        var hint string
        var hintCost int
        err := db.QueryRow(`
            SELECT hint, hint_cost 
            FROM machine_questions 
            WHERE id = $1 AND machine_id = $2
        `, questionID, machineID).Scan(&hint, &hintCost)

        if err != nil {
            http.Error(w, "İpucu bulunamadı", http.StatusNotFound)
            return
        }

        // Kullanıcının puanı yeterli mi?
        var userPoints int
        db.QueryRow("SELECT points FROM users WHERE id = $1", userID).Scan(&userPoints)

        if userPoints < hintCost {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Yetersiz puan!",
            })
            return
        }

        // Puanı düş
        db.Exec("UPDATE users SET points = points - $1 WHERE id = $2", hintCost, userID)

        // İpucu kullanımını logla
        db.Exec(`
            INSERT INTO hint_usage (user_id, machine_id, question_id, used_at)
            VALUES ($1, $2, $3, NOW())
        `, userID, machineID, questionID)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "hint":    hint,
            "cost":    hintCost,
        })
    }
}

func TerminalWebSocket(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // vars := mux.Vars(r)
        // sessionID := vars["sessionId"]

        // // Session kontrolü
        // session, _ := store.Get(r, "session")
        // if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        //     http.Error(w, "Yetkisiz erişim", http.StatusUnauthorized)
        //     return
        // }

        // WebSocket bağlantısını yükselt
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer conn.Close()

        // Terminal session'ını başlat
        // Docker container'a bağlan veya PTY oluştur
        
        for {
            _, message, err := conn.ReadMessage()
            if err != nil {
                break
            }

            // Komutu işle ve sonucu gönder
            response := executeCommand(string(message))
            conn.WriteMessage(websocket.TextMessage, []byte(response))
        }
    }
}

// Terminal komutlarını işle (mock)
func executeCommand(cmd string) string {
    switch cmd {
    case "ls":
        return "flag.txt  README.md  scripts  notes.txt\n"
    case "pwd":
        return "/root\n"
    case "whoami":
        return "root\n"
    default:
        return "Command not found: " + cmd + "\n"
    }
}