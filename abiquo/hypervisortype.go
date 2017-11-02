package abiquo_api

type HypervisorTypeCollection struct {
	AbstractCollection
	Collection []HypervisorType
}

type HypervisorType struct {
	DTO
	Name                string                       `json:"name,omitempty"`
	RealName            string                       `json:"realName,omitempty"`
	Constraints         map[string]string            `json:"constraints,omitempty"`
	Operations          map[string]map[string]string `json:"operations,omitempty"`
	Baseformat          string                       `json:"baseformat,omitempty"`
	Compatibleformats   []string                     `json:"compatibleformats,omitempty"`
	Diskcontrollertypes []string                     `json:"diskcontrollertypes,omitempty"`
	Guestsetups         []interface{}                `json:"guestsetups,omitempty"`
	Diskallocationtypes []interface{}                `json:"diskallocationtypes,omitempty"`
}
