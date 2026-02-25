package models

import (
	
	"time"
)

type AdminDashboardData struct {
	Title             string
	Stats             AdminStats
	RecentUsers       []User
	RecentSubmissions []Submission
	SystemHealth      SystemHealth
	PopularMachines   []PopularMachine
	ActivityChart     ChartData
	CurrentDate       string
	ActivePercentage  float64
	Admin             Admin
	Active            string
}

type Admin struct {
	Username string
	Role     string
	Avatar   string
}

type AdminStats struct {
	TotalUsers       int     `json:"total_users"`
	NewUsersToday    int     `json:"new_users_today"`
	ActiveUsers      int     `json:"active_users"`
	TotalMachines    int     `json:"total_machines"`
	TotalSubmissions int     `json:"total_submissions"`
	SubmissionsToday int     `json:"submissions_today"`
	TotalVIPUsers    int     `json:"total_vip_users"`
	VIPRevenue       float64 `json:"vip_revenue"`
	AveragePoints    float64 `json:"average_points"`
	TopUserPoints    int     `json:"top_user_points"`
	SuccessRate      float64 `json:"success_rate"`
}

type Submission struct {
	ID            int       `json:"id"`
	Username      string    `json:"username"`
	MachineName   string    `json:"machine_name"`
	QuestionTitle string    `json:"question_title"`
	Status        string    `json:"status"`
	SubmittedAt   time.Time `json:"submitted_at"`
}

type SystemHealth struct {
	Status              string  `json:"status"`
	CPUUsage            float64 `json:"cpu_usage"`
	MemoryUsage         float64 `json:"memory_usage"`
	DiskUsage           float64 `json:"disk_usage"`
	ActiveContainers    int     `json:"active_containers"`
	DatabaseConnections int     `json:"db_connections"`
}

type PopularMachine struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Difficulty  string `json:"difficulty"`
	Submissions int    `json:"submissions"`
	SuccessRate int    `json:"success_rate"`
}

type ChartData struct {
	Labels   []string       `json:"labels"`
	Datasets []ChartDataset `json:"datasets"`
}

type ChartDataset struct {
	Label string `json:"label"`
	Data  []int  `json:"data"`
}
