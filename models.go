package main

type User struct {
	ID          int
	Username    string
	DisplayName string
	Password    string
}

type SafeIP struct {
	IP          string `json:"ip"`
	Description string `json:"description"`
}

type FirewallRuleGroup struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	DestIP      string `json:"dest_ip"`
	DestPort    string `json:"dest_port"`
	CreatedAt   string `json:"created_at"`
}

type FirewallRuleSource struct {
	ID          int    `json:"id"`
	GroupID     int    `json:"group_id"`
	SourceIP    string `json:"source_ip"`
	SourcePort  string `json:"source_port"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

type exportSource struct {
	SourceIP    string `json:"source_ip"`
	SourcePort  string `json:"source_port"`
	Description string `json:"description"`
}

type exportGroup struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Action      string         `json:"action"`
	Protocol    string         `json:"protocol"`
	DestIP      string         `json:"dest_ip"`
	DestPort    string         `json:"dest_port"`
	Sources     []exportSource `json:"sources"`
}
