package abiquo_api

type FirewallRuleCollection struct {
	AbstractCollection
	Collection []FirewallRule `json:"collection,omitempty"`
}

type FirewallRule struct {
	DTO
	Protocol string   `json:"protocol,omitempty"`
	FromPort int      `json:"fromPort"`
	ToPort   int      `json:"toPort"`
	Targets  []string `json:"targets,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}
