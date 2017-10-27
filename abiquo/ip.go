package abiquo_api

import (
	"encoding/json"
	"errors"
	"fmt"
)

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

func (i *Ip) PurchasePublicIp(c *AbiquoClient) (Ip, error) {
	var ip Ip
	purchase_lnk, err := i.GetLink("purchase")
	if err != nil {
		errorMsg := fmt.Sprintf("Ip {%v} can't be purchased.", i)
		return ip, errors.New(errorMsg)
	}
	purchase_resp, err := c.checkResponse(c.client.R().
		SetHeader("Accept", "application/vnd.abiquo.publicip+json").
		SetHeader("Content-Type", "application/vnd.abiquo.publicip+json").
		Put(purchase_lnk.Href))
	if err != nil {
		return ip, err
	}
	json.Unmarshal(purchase_resp.Body(), &ip)
	return ip, nil
}
