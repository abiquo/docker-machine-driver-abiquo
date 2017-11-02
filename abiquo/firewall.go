package abiquo_api

import (
	"encoding/json"
	"log"
)

type FirewallCollection struct {
	AbstractCollection
	Collection []Firewall
}

type Firewall struct {
	DTO
	Name        string `json:"name,omitempty"`
	ProviderID  string `json:"providerId,omitempty"`
	Description string `json:"description,omitempty"`
}

func (f *Firewall) GetRules(c *AbiquoClient) ([]FirewallRule, error) {
	var rules []FirewallRule
	var rulescol FirewallRuleCollection

	rules_lnk, _ := f.GetLink("rules")
	rules_resp, err := f.FollowLink("rules", c)
	if err != nil {
		return rules, err
	}
	json.Unmarshal(rules_resp.Body(), &rulescol)

	for {
		for _, r := range rulescol.Collection {
			rules = append(rules, r)
		}
		if rulescol.HasNext() {
			next_link := rulescol.GetNext()
			rules_resp, err := c.checkResponse(c.client.R().SetHeader("Accept", rules_lnk.Type).
				Get(next_link.Href))
			if err != nil {
				return rules, err
			}
			json.Unmarshal(rules_resp.Body(), &rulescol)
		} else {
			break
		}
	}
	return rules, nil
}

func (f *Firewall) SetRules(rules []FirewallRule, c *AbiquoClient) error {
	rules_lnk, _ := f.GetLink("rules")

	rulesCollection := FirewallRuleCollection{
		Collection: rules,
	}
	rulesStr, _ := json.Marshal(rulesCollection)
	log.Printf("Rules JSON: '%s'", rulesStr)
	_, err := c.checkResponse(c.client.R().
		SetHeader("Accept", "application/vnd.abiquo.firewallrules+json").
		SetHeader("Content-Type", "application/vnd.abiquo.firewallrules+json").
		SetBody(rulesStr).
		Put(rules_lnk.Href))
	return err
}
