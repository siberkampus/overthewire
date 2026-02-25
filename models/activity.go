// models/activity.go

package models

import "time"

type Activity struct {
	Type       string    `json:"type"`
	MachineID  *int      `json:"machine_id"`
	QuestionID *int      `json:"question_id"`
	BadgeID    *int      `json:"badge_id"`
	Points     *int      `json:"points"`
	CreatedAt  time.Time `json:"created_at"`
}

type Badge struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Icon        string    `json:"icon"`
	EarnedAt    time.Time `json:"earned_at"`
}

type Achievement struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Points      int    `json:"points"`
}

type Follower struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Avatar   string `json:"avatar"`
}

type Solver struct {
	Username string    `json:"username"`
	Avatar   string    `json:"avatar"`
	SolvedAt time.Time `json:"solved_at"`
}

type UserProgress struct {
	SolvedQuestions int `json:"solved_questions"`
	TotalQuestions  int `json:"total_questions"`
}
