package abiquo_api

type DeviceTypeCollection struct {
	AbstractCollection
	Collection []DeviceType
}

type DeviceType struct {
	DTO
	Name             string            `json:"name,omitempty"`
	DeviceInterfaces []DeviceInterface `json:"deviceinterfaces,omitempty"`
}

type DeviceInterface struct {
	DeviceInterface string `json:"deviceInterface,omitempty"`
	RealName        string `json:"realName,omitempty"`
	Constraints     struct {
	} `json:"constraints,omitempty"`
	Operations struct {
		Vpc struct {
		} `json:"vpc,omitempty"`
	} `json:"operations,omitempty"`
}
