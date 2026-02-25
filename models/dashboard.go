package models


type DashboardData struct {
	Title           string
	User            *User
	IsAuthenticated bool
	Stats           DashboardStats
	RecentActivity  []Activity
	InProgress      []InProgressMachine
	Achievements    []Achievement
	ChartData       ChartData
}

type DashboardStats struct {
	TotalPoints   int
	TotalSolved   int
	TotalMachines int
	Rank          int
	DailyGoal     int
	DailyProgress int
	Streak        int
	VIPCount      int
}

type Dataset struct {
	Label string
	Data  []int
}
