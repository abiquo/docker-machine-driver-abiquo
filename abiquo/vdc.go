package abiquo_api

import (
	"encoding/json"
	"errors"
	"fmt"
)

type VdcCollection struct {
	AbstractCollection
	Collection []VDC
}

type VDC struct {
	DTO
	HypervisorType    string `json:"hypervisorType,omitempty"`
	Name              string `json:"name,omitempty"`
	SyncState         string `json:"syncState,omitempty"`
	DiskSoftLimitInMb int    `json:"diskSoftLimitInMb,omitempty"`
	DiskHardLimitInMb int    `json:"diskHardLimitInMb,omitempty"`
	StorageSoftInMb   int    `json:"storageSoftInMb,omitempty"`
	StorageHardInMb   int    `json:"storageHardInMb,omitempty"`
	VlansSoft         int    `json:"vlansSoft,omitempty"`
	VlansHard         int    `json:"vlansHard,omitempty"`
	PublicIpsSoft     int    `json:"publicIpsSoft,omitempty"`
	PublicIpsHard     int    `json:"publicIpsHard,omitempty"`
	RAMSoft           int    `json:"ramSoft,omitempty"`
	RAMHard           int    `json:"ramHard,omitempty"`
	CPUSoft           int    `json:"cpuSoft,omitempty"`
	CPUHard           int    `json:"cpuHard,omitempty"`
}

func (v *VDC) GetVirtualApps(c *AbiquoClient) ([]VirtualApp, error) {
	var allVapps []VirtualApp
	var vapps VirtualAppCollection
	vapps_raw, err := v.FollowLink("virtualappliances", c)
	if err != nil {
		return allVapps, err
	}
	json.Unmarshal(vapps_raw.Body(), &vapps)
	for {
		for _, va := range vapps.Collection {
			allVapps = append(allVapps, va)
		}
		if vapps.HasNext() {
			next_link := vapps.GetNext()
			vapps_raw, err := c.checkResponse(c.client.R().SetHeader("Accept", "application/vnd.abiquo.virtualappliances+json").
				Get(next_link.Href))
			if err != nil {
				return allVapps, err
			}
			json.Unmarshal(vapps_raw.Body(), &vapps)
		} else {
			break
		}
	}
	return allVapps, nil
}

func (v *VDC) GetTemplate(template_name string, c *AbiquoClient) (VirtualMachineTemplate, error) {
	var vt VirtualMachineTemplate
	templates, err := v.GetTemplates(c)
	if err != nil {
		return vt, err
	}
	for _, t := range templates {
		if t.Name == template_name {
			return t, nil
		}
	}
	errorMsg := fmt.Sprintf("Template '%s' not found in VDC '%s'", template_name, v.Name)
	return vt, errors.New(errorMsg)
}

func (v *VDC) GetTemplates(c *AbiquoClient) ([]VirtualMachineTemplate, error) {
	var templates TemplateCollection
	var alltemplates []VirtualMachineTemplate

	templates_raw, err := v.FollowLink("templates", c)
	if err != nil {
		return alltemplates, err
	}

	json.Unmarshal(templates_raw.Body(), &templates)
	for {
		for _, t := range templates.Collection {
			alltemplates = append(alltemplates, t)
		}

		if templates.HasNext() {
			next_link := templates.GetNext()
			templates_raw, err = c.checkResponse(c.client.R().SetHeader("Accept", "application/vnd.abiquo.virtualmachinetemplates+json").
				Get(next_link.Href))
			if err != nil {
				return alltemplates, err
			}
			json.Unmarshal(templates_raw.Body(), &templates)
		} else {
			break
		}
	}

	return alltemplates, nil
}

func (v *VDC) GetHardwareProfiles(c *AbiquoClient) ([]HWprofile, error) {
	var allProfiles []HWprofile
	var hprofiles HWprofileCollection
	var location Location

	location_raw, err := v.FollowLink("location", c)
	if err != nil {
		return allProfiles, err
	}
	json.Unmarshal(location_raw.Body(), &location)

	/// https://jira.abiquo.com/browse/ABICLOUDPREMIUM-9957
	///
	// profiles_raw, err := location.FollowLink("hardwareprofiles", c)
	// if err != nil {
	// 	return allProfiles, err
	// }

	profiles_lnk, _ := location.GetLink("hardwareprofiles")
	profiles_raw, err := c.checkResponse(c.client.R().
		SetHeader("Accept", profiles_lnk.Type).
		SetQueryParam("limit", "0").
		Get(profiles_lnk.Href))
	if err != nil {
		return allProfiles, err
	}
	json.Unmarshal(profiles_raw.Body(), &hprofiles)

	// for {
	for _, hp := range hprofiles.Collection {
		allProfiles = append(allProfiles, hp)
	}

	// if hprofiles.HasNext() {
	// 	next_link := hprofiles.GetNext()
	// 	profiles_raw, err = c.checkResponse(c.client.R().SetHeader("Accept", "application/vnd.abiquo.hardwareprofiles+json").
	// 		Get(next_link.Href))
	// 	if err != nil {
	// 		return allProfiles, err
	// 	}
	// 	json.Unmarshal(profiles_raw.Body(), &hprofiles)
	// } else {
	// 	break
	// }
	// }

	return allProfiles, nil
}

func (v *VDC) CreateVapp(vapp_name string, c *AbiquoClient) (VirtualApp, error) {
	var vapp VirtualApp
	vapps_lnk, _ := v.GetLink("virtualappliances")

	vapp.Name = vapp_name
	jsonbytes, err := json.Marshal(vapp)
	if err != nil {
		return vapp, err
	}
	vapp_raw, err := c.checkResponse(c.checkResponse(c.client.R().SetHeader("Accept", "application/vnd.abiquo.virtualappliance+json").
		SetHeader("Content-Type", "application/vnd.abiquo.virtualappliance+json").
		SetBody(jsonbytes).
		Post(vapps_lnk.Href)))
	if err != nil {
		return vapp, err
	}
	json.Unmarshal(vapp_raw.Body(), &vapp)
	return vapp, nil
}

func (v *VDC) GetExternalNetworks(c *AbiquoClient) ([]Vlan, error) {
	var netCol VlanCollection
	var nets []Vlan

	nets_resp, err := v.FollowLink("externalnetworks", c)
	if err != nil {
		return nets, err
	}
	json.Unmarshal(nets_resp.Body(), &netCol)

	for {
		for _, n := range netCol.Collection {
			nets = append(nets, n)
		}

		if netCol.HasNext() {
			next_link := netCol.GetNext()
			nets_resp, err = c.checkResponse(c.client.R().SetHeader("Accept", "application/vnd.abiquo.vlans+json").
				Get(next_link.Href))
			if err != nil {
				return nets, err
			}
			json.Unmarshal(nets_resp.Body(), &netCol)
		} else {
			break
		}
	}

	return nets, nil
}

func (v *VDC) GetPrivateNetworks(c *AbiquoClient) ([]Vlan, error) {
	var netCol VlanCollection
	var nets []Vlan

	nets_resp, err := v.FollowLink("privatenetworks", c)
	if err != nil {
		return nets, err
	}
	json.Unmarshal(nets_resp.Body(), &netCol)

	for {
		for _, n := range netCol.Collection {
			nets = append(nets, n)
		}

		if netCol.HasNext() {
			next_link := netCol.GetNext()
			nets_resp, err = c.checkResponse(c.client.R().SetHeader("Accept", "application/vnd.abiquo.vlans+json").
				Get(next_link.Href))
			if err != nil {
				return nets, err
			}
			json.Unmarshal(nets_resp.Body(), &netCol)
		} else {
			break
		}
	}

	return nets, nil
}

func (v *VDC) GetNetworks(c *AbiquoClient) ([]Vlan, error) {
	privnets, err := v.GetPrivateNetworks(c)
	if err != nil {
		return nil, err
	}

	extnets, err := v.GetExternalNetworks(c)
	if err != nil {
		return nil, err
	}

	return append(extnets, privnets...), nil
}

func (v *VDC) IsPCR() bool {
	location_lnk, _ := v.GetLink("location")

	if location_lnk.Type == "application/vnd.abiquo.publiccloudregion+json" {
		return true
	} else {
		return false
	}
}

func (v *VDC) AllocateFloatingIp(c *AbiquoClient) (Ip, error) {
	var floating Ip
	var theIp Ip
	var location Location

	location_resp, err := v.FollowLink("location", c)
	if err != nil {
		return floating, err
	}
	json.Unmarshal(location_resp.Body(), &location)

	ips_lnk, _ := location.GetLink("ips")

	floating_resp, err := c.checkResponse(c.client.R().
		SetHeader("Accept", "application/vnd.abiquo.publicip+json").
		SetHeader("Content-Type", "application/vnd.abiquo.publicip+json").
		Post(ips_lnk.Href))
	if err != nil {
		return floating, err
	}
	json.Unmarshal(floating_resp.Body(), &floating)

	var topurchase IpCollection
	topurchase_resp, err := v.FollowLink("topurchase", c)
	if err != nil {
		return theIp, err
	}
	json.Unmarshal(topurchase_resp.Body(), &topurchase)

	for {
		for _, i := range topurchase.Collection {
			if i.IP == floating.IP {
				return i.PurchasePublicIp(c)
			}
		}
		if topurchase.HasNext() {
			next_link := topurchase.GetNext()
			topurchase_resp, err := c.checkResponse(c.client.R().
				SetHeader("Accept", "application/vnd.abiquo.publicips+json").
				SetHeader("Content-Type", "application/vnd.abiquo.publicips+json").
				Get(next_link.Href))
			if err != nil {
				return theIp, err
			}
			json.Unmarshal(topurchase_resp.Body(), &topurchase)
		} else {
			break
		}
	}
	errorMsg := fmt.Sprintf("Could not find floating IP to purchase!")
	return theIp, errors.New(errorMsg)
}

func (v *VDC) GetPublicNetworks(c *AbiquoClient) ([]Vlan, error) {
	var netCol VlanCollection
	var nets []Vlan

	myLink, _ := v.GetLink("edit")
	pubnets_resp, err := c.checkResponse(c.client.R().
		SetHeader("Accept", "application/vnd.abiquo.vlans+json").
		Get(fmt.Sprintf("%s/publicvlans", myLink.Href)))
	if err != nil {
		return nets, err
	}
	json.Unmarshal(pubnets_resp.Body(), &netCol)

	for {
		for _, n := range netCol.Collection {
			nets = append(nets, n)
		}
		if netCol.HasNext() {
			next_link := netCol.GetNext()
			pubnets_resp, err := c.checkResponse(c.client.R().SetHeader("Accept", "application/vnd.abiquo.vlans+json").
				Get(next_link.Href))
			if err != nil {
				return nets, err
			}
			json.Unmarshal(pubnets_resp.Body(), &netCol)
		} else {
			break
		}
	}
	return nets, nil
}

func (v *VDC) GetIpsToPurchase(c *AbiquoClient) ([]Ip, error) {
	var ips []Ip
	var ipCol IpCollection

	ips_link, _ := v.GetLink("topurchase")
	ips_resp, err := v.FollowLink("topurchase", c)
	if err != nil {
		return ips, err
	}
	json.Unmarshal(ips_resp.Body(), &ipCol)

	for {
		for _, i := range ipCol.Collection {
			ips = append(ips, i)
		}
		if ipCol.HasNext() {
			next_link := ipCol.GetNext()
			ips_resp, err := c.checkResponse(c.client.R().SetHeader("Accept", ips_link.Type).
				Get(next_link.Href))
			if err != nil {
				return ips, err
			}
			json.Unmarshal(ips_resp.Body(), &ipCol)
		} else {
			break
		}
	}

	return ips, nil
}

func (v *VDC) AllocatePublicIp(c *AbiquoClient, netName string) (Ip, error) {
	var theIp Ip

	ips, err := v.GetIpsToPurchase(c)
	if err != nil {
		return theIp, nil
	}

	if netName != "" {
		for _, i := range ips {
			net_link, _ := i.GetLink("publicnetwork")
			if netName == net_link.Title {
				_, err := i.GetLink("virtualmachine")
				if err != nil {
					return i.PurchasePublicIp(c)
				}
			}
		}
	} else {
		for _, i := range ips {
			_, err := i.GetLink("virtualmachine")
			if err != nil {
				return i.PurchasePublicIp(c)
			}
		}
	}

	errorMsg := "Could not allocate a public IP in this VDC."
	return theIp, errors.New(errorMsg)
}

func (v *VDC) GetDevice(c *AbiquoClient) (Device, error) {
	var dev Device

	_, err := v.GetLink("device")
	if err != nil {
		return dev, err
	}

	dev_resp, err := v.FollowLink("device", c)
	if err != nil {
		return dev, err
	}
	json.Unmarshal(dev_resp.Body(), &dev)
	return dev, nil
}
