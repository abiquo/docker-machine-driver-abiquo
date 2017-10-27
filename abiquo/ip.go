package abiquo_api

type IpCollection struct {
	AbstractCollection
	Collection []Ip
}

type Ip struct {
	DTO
	IP          string `json:"ip,omitempty"`
	Mac         string `json:"mac,omitempty"`
	Name        string `json:"name,omitempty"`
	NetworkName string `json:"networkName,omitempty"`
	Ipv6        bool   `json:"ipv6,omitempty"`
	Available   bool   `json:"available,omitempty"`
}
