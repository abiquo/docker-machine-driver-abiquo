package abiquo_api

import (
	"encoding/json"
	"errors"
	"fmt"
)

type DeviceCollection struct {
	AbstractCollection
	Collection []Device
}

type Device struct {
	DTO
	Endpoint   string `json:"endpoint,omitempty"`
	Name       string `json:"name,omitempty"`
	VdcDefault bool   `json:"vdcDefault,omitempty"`
}

func (d *Device) SupportsFirewall(c *AbiquoClient) (bool, error) {
	_, err := d.GetLink("devicetype")
	if err != nil {
		_, err = d.GetLink("hypervisortype")
		if err != nil {
			errorMsg := fmt.Sprintf("The device type for device '%s' is unknown", d.Name)
			return false, errors.New(errorMsg)
		}
		return d.checkHtypeForFirewall(c)
	}
	return d.checkDeviceForFirewall(c)
}

func (d *Device) checkDeviceForFirewall(c *AbiquoClient) (bool, error) {
	var dtype DeviceType

	devtype_resp, err := d.FollowLink("devicetype", c)
	if err != nil {
		return false, err
	}
	json.Unmarshal(devtype_resp.Body(), &dtype)

	for _, i := range dtype.DeviceInterfaces {
		if i.DeviceInterface == "Firewall" {
			return true, nil
		}
	}
	return false, nil
}

func (d *Device) checkHtypeForFirewall(c *AbiquoClient) (bool, error) {
	var htype HypervisorType

	htype_resp, err := d.FollowLink("hypervisortype", c)
	if err != nil {
		return false, err
	}
	json.Unmarshal(htype_resp.Body(), &htype)

	if _, exist := htype.Operations["firewall"]; exist {
		return true, nil
	} else {
		return false, nil
	}
}

func (d *Device) CreateFirewall(v VDC, name string, description string, c *AbiquoClient) (Firewall, error) {
	var fw Firewall

	vdc_lnk, _ := v.GetLink("edit")
	vdc_lnk.Rel = "virtualdatacenter"

	supportsFw, err := d.SupportsFirewall(c)
	if err != nil {
		return fw, err
	}
	if !supportsFw {
		errorMsg := fmt.Sprintf("Device '%s' does not support firewalls.", d.Name)
		return fw, errors.New(errorMsg)
	}

	fw = Firewall{
		Name:        name,
		Description: description,
	}
	fw.Links = append(fw.Links, vdc_lnk)

	strBody, _ := json.Marshal(fw)

	firewalls_lnk, _ := d.GetLink("firewalls")
	firewall_resp, err := c.checkResponse(c.client.R().
		SetHeader("Content-Type", "application/vnd.abiquo.firewallpolicy+json").
		SetHeader("Accept", "application/vnd.abiquo.firewallpolicy+json").
		SetBody(strBody).
		Post(firewalls_lnk.Href))
	if err != nil {
		return fw, err
	}
	json.Unmarshal(firewall_resp.Body(), &fw)
	return fw, nil
}

func (d *Device) GetFirewalls(c *AbiquoClient) ([]Firewall, error) {
	var fws []Firewall
	var fwCol FirewallCollection

	fws_link, err := d.GetLink("firewalls")
	if err != nil {
		return fws, err
	}

	fws_resp, err := d.FollowLink("firewalls", c)
	if err != nil {
		return fws, err
	}
	json.Unmarshal(fws_resp.Body(), &fwCol)

	for {
		for _, f := range fwCol.Collection {
			fws = append(fws, f)
		}
		if fwCol.HasNext() {
			next_link := fwCol.GetNext()
			fws_resp, err := c.checkResponse(c.client.R().SetHeader("Accept", fws_link.Type).
				Get(next_link.Href))
			if err != nil {
				return fws, err
			}
			json.Unmarshal(fws_resp.Body(), &fwCol)
		} else {
			break
		}
	}

	return fws, nil
}
