// models/leaderboard.go

package models

type LeaderboardEntry struct {
    ID             int    `json:"id"`
    Username       string `json:"username"`
    Avatar         string `json:"avatar"`
    Country        string `json:"country"`
    Points         int    `json:"points"`
    Rank           int    `json:"rank"`
    IsVIP          bool   `json:"is_vip"`
    MachinesSolved int    `json:"machines_solved"`
    QuestionsSolved int   `json:"questions_solved"`
    Accuracy       int    `json:"accuracy"`
}

