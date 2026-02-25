// models/machine.go

package models

import "time"

type Machine struct {
	ID             int        `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Difficulty     string     `json:"difficulty"`
	PointsReward   int        `json:"points_reward"`
	IsVIPOnly      bool       `json:"is_vip_only"`
	DockerImage    string     `json:"docker_image"`
	Creator        string     `json:"creator"`
	SolverCount    int        `json:"solver_count"`
	TotalQuestions int        `json:"total_questions"`
	Questions      []Question `json:"questions,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	IsActive       bool       `json:"is_active"`
	ImageURL	   string     `json:"image_url"`
}

type Question struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	FlagHash     string `json:"flag"`
	PointsReward int    `json:"points_reward"`
	Hint         string `json:"hint"`
	HintCost     int    `json:"hint_cost"`
	Solved       bool   `json:"solved"`
	IsActive     bool   `json:"is_active"`
}

type SolvedMachine struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	Difficulty string    `json:"difficulty"`
	Points     int       `json:"points"`
	SolvedAt   time.Time `json:"solved_at"`
}

type InProgressMachine struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Difficulty string `json:"difficulty"`
	Solved     int    `json:"solved"`
	Total      int    `json:"total"`
}
