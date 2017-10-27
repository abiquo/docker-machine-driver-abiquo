package abiquo_api

import (
	"encoding/json"
	"errors"
	"fmt"
)

type VlanCollection struct {
	AbstractCollection
	Collection []Vlan
}

type Vlan struct {
	DTO
	Name                string `json:"name,omitempty"`
	Address             string `json:"address,omitempty"`
	Mask                int    `json:"mask,omitempty"`
	Gateway             string `json:"gateway,omitempty"`
	PrimaryDNS          string `json:"primaryDNS,omitempty"`
	SecondaryDNS        string `json:"secondaryDNS,omitempty"`
	SufixDNS            string `json:"sufixDNS,omitempty"`
	DefaultNetwork      bool   `json:"defaultNetwork,omitempty"`
	Tag                 int    `json:"tag,omitempty"`
	Type                string `json:"type,omitempty"`
	Ipv6                bool   `json:"ipv6,omitempty"`
	Strict              bool   `json:"strict,omitempty"`
	ProviderID          string `json:"providerId,omitempty"`
	Restricted          bool   `json:"restricted,omitempty"`
	InternetGatewayRole bool   `json:"internetGatewayRole,omitempty"`
	IPRanges            []struct {
		FirstIP string `json:"firstIp,omitempty"`
		LastIP  string `json:"lastIp,omitempty"`
	} `json:"ipRanges,omitempty"`
}

func (v *Vlan) GetFreeIp(c *AbiquoClient) (Ip, error) {
	var ipcol IpCollection
	var ip Ip

	ips_resp, err := v.FollowLink("ips", c)
	if err != nil {
		return ip, err
	}
	json.Unmarshal(ips_resp.Body(), &ipcol)

	for {
		for _, i := range ipcol.Collection {
			_, err := i.GetLink("virtualmachine")
			if err != nil {
				if i.Available {
					return i, nil
				}
			}
		}
		if ipcol.HasNext() {
			next_link := ipcol.GetNext()
			ips_resp, err := c.checkResponse(c.client.R().
				Get(next_link.Href))
			if err != nil {
				return ip, err
			}
			json.Unmarshal(ips_resp.Body(), &ipcol)
		} else {
			break
		}
	}
	errorMsg := fmt.Sprintf("Could not find a free IP in network '%s'", v.Name)
	return ip, errors.New(errorMsg)
}
