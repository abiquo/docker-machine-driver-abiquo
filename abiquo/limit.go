package abiquo_api

import (
	"encoding/json"
)

type LimitCollection struct {
	AbstractCollection
	Collection []Limit
}

type Limit struct {
	DTO
	EnabledHardwareProfiles bool `json:"enabledHardwareProfiles,omitempty"`
	DiskSoftLimitInMb       int  `json:"diskSoftLimitInMb,omitempty"`
	DiskHardLimitInMb       int  `json:"diskHardLimitInMb,omitempty"`
	StorageSoftInMb         int  `json:"storageSoftInMb,omitempty"`
	StorageHardInMb         int  `json:"storageHardInMb,omitempty"`
	VlansSoft               int  `json:"vlansSoft,omitempty"`
	VlansHard               int  `json:"vlansHard,omitempty"`
	PublicIpsSoft           int  `json:"publicIpsSoft,omitempty"`
	PublicIpsHard           int  `json:"publicIpsHard,omitempty"`
	RepositorySoftInMb      int  `json:"repositorySoftInMb,omitempty"`
	RepositoryHardInMb      int  `json:"repositoryHardInMb,omitempty"`
	RAMSoft                 int  `json:"ramSoft,omitempty"`
	RAMHard                 int  `json:"ramHard,omitempty"`
	CPUSoft                 int  `json:"cpuSoft,omitempty"`
	CPUHard                 int  `json:"cpuHard,omitempty"`
}

func (l *Limit) GetHardwareProfiles(c *AbiquoClient) ([]HWprofile, error) {
	var allProfiles []HWprofile
	if !l.EnabledHardwareProfiles {
		return allProfiles, nil
	}

	for _, link := range l.Links {
		if link.Rel == "hardwareprofile" {
			link.trimPort()
			var hp HWprofile
			hp_raw, err := c.checkResponse(c.client.R().SetHeader("Accept", link.Type).
				Get(link.Href))
			if err != nil {
				return allProfiles, err
			}
			json.Unmarshal(hp_raw.Body(), &hp)
			allProfiles = append(allProfiles, hp)
		}
	}
	return allProfiles, nil
}
