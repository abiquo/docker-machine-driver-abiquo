package abiquo_api

type TemplateCollection struct {
	AbstractCollection
	Collection []VirtualMachineTemplate
}

type VirtualMachineTemplate struct {
	DTO
	Name                             string `json:"name,omitempty"`
	ChefEnabled                      bool   `json:"chefEnabled,omitempty"`
	CpuRequired                      int    `json:"cpuRequired,omitempty"`
	CreationDate                     string `json:"creationDate,omitempty"`
	CreationUser                     string `json:"creationUser,omitempty"`
	Description                      string `json:"description,omitempty"`
	EthernetDriverType               string `json:"ethernetDriverType,omitempty"`
	IconUrl                          string `json:"iconUrl,omitempty"`
	Id                               int    `json:"id,omitempty"`
	LoginPassword                    string `json:"loginPassword,omitempty"`
	LoginUser                        string `json:"loginUser,omitempty"`
	OsType                           string `json:"osType,omitempty"`
	OsVersion                        string `json:"osVersion,omitempty"`
	RamRequired                      int    `json:"ramRequired,omitempty"`
	State                            string `json:"state,omitempty"`
	EnableCpuHotAdd                  bool   `json:"enableCpuHotAdd,omitempty"`
	EnableRamHotAdd                  bool   `json:"enableRamHotAdd,omitempty"`
	EnableDisksHotReconfigure        bool   `json:"enableDisksHotReconfigure,omitempty"`
	EnableNicsHotReconfigure         bool   `json:"enableNicsHotReconfigure,omitempty"`
	EnableRemoteAccessHotReconfigure bool   `json:"enableRemoteAccessHotReconfigure,omitempty"`
}
