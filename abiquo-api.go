package abiquo

import (
	"encoding/json"
	"errors"
	"fmt"
	// "net/http"
	"strings"
	"time"

	"gopkg.in/resty.v0"
)

type DTO struct {
	Links []Link `json:"links,omitempty"`
}

func (d *DTO) FollowLink(rel string, c *resty.Request) (*resty.Response, error) {
	for _, l := range d.Links {
		if l.Rel == rel {
			resp, error := c.SetHeader("Accept", l.Type).
				Get(l.Href)
			return resp, error
		}
	}
	errorMsg := fmt.Sprintf("Link with rel '%s' not found", rel)
	var r resty.Response
	return &r, errors.New(errorMsg)
}

func (d *DTO) GetLink(rel string) (Link, error) {
	var link Link
	for _, l := range d.Links {
		if l.Rel == rel {
			return l, nil
		}
	}
	errorMsg := fmt.Sprintf("Link with rel '%s' not found", rel)
	return link, errors.New(errorMsg)
}

func (d *DTO) Refresh(c *resty.Request) (*resty.Response, error) {
	edit_lnk, err := d.GetLink("edit")
	if err != nil {
		edit_lnk, _ = d.GetLink("self")
	}
	return c.SetHeader("Accept", edit_lnk.Type).
		SetHeader("Content-Type", edit_lnk.Type).
		Get(edit_lnk.Href)
}

type Link struct {
	Type  string `json:"type,omitempty"`
	Href  string `json:"href,omitempty"`
	Title string `json:"title,omitempty"`
	Rel   string `json:"rel,omitempty"`
}

func (l *Link) Get(c *resty.Request) (*resty.Response, error) {
	resp, err := c.SetHeader("Accept", l.Type).Get(l.Href)
	return resp, err
}

type AbstractCollection struct {
	Links     []Link
	TotalSize int
}

func (c *AbstractCollection) GetNext() Link {
	var l Link
	for _, link := range c.Links {
		if link.Rel == "next" {
			l = link
		}
	}
	return l
}

func (c *AbstractCollection) HasNext() bool {
	for _, link := range c.Links {
		if link.Rel == "next" {
			return true
		}
	}
	return false
}

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

type VirtualAppCollection struct {
	AbstractCollection
	Collection []VirtualApp
}

type VirtualApp struct {
	DTO
	Error             int    `json:"error,omitempty"`
	HighDisponibility int    `json:"highDisponibility,omitempty"`
	Name              string `json:"name,omitempty"`
	PublicApp         int    `json:"publicApp,omitempty"`
	State             string `json:"state,omitempty"`
}

func (v *VirtualApp) Delete(c *resty.Request) error {
	edit_lnk, _ := v.GetLink("edit")
	_, err := c.Delete(edit_lnk.Href)
	if err != nil {
		return err
	}

	return nil

}

func (v *VirtualApp) GetVMs(c *resty.Request) ([]VirtualMachine, error) {
	var vms []VirtualMachine
	var vmsCol VirtualMachineCollection
	vms_raw, err := v.FollowLink("virtualmachines", c)
	if err != nil {
		return vms, err
	}
	json.Unmarshal(vms_raw.Body(), &vmsCol)

	for {
		for _, vm := range vmsCol.Collection {
			vms = append(vms, vm)
		}

		if vmsCol.HasNext() {
			next_link := vmsCol.GetNext()
			vms_raw, err = c.SetHeader("Accept", "application/vnd.abiquo.virtualmachines+json").
				Get(next_link.Href)
			if err != nil {
				return vms, err
			}
			json.Unmarshal(vms_raw.Body(), &vmsCol)
		} else {
			break
		}
	}
	return vms, nil
}

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

type HWprofile struct {
	DTO
	Name   string `json:"name,omitempty"`
	Cpu    int    `json:"cpu,omitempty"`
	Ram    int    `json:"ramInMb,omitempty"`
	Active bool   `json:"active,omitempty"`
}

func (v *VDC) GetVirtualApps(c *resty.Request) ([]VirtualApp, error) {
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
			vapps_raw, err := c.SetHeader("Accept", "application/vnd.abiquo.virtualappliances+json").
				Get(next_link.Href)
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

func (v *VDC) GetTemplate(template_name string, c *resty.Request) (VirtualMachineTemplate, error) {
	var vt VirtualMachineTemplate
	var templates TemplateCollection
	var alltemplates []VirtualMachineTemplate

	templates_raw, err := v.FollowLink("templates", c)
	if err != nil {
		return vt, err
	}

	json.Unmarshal(templates_raw.Body(), &templates)
	for templates.HasNext() {
		for _, t := range templates.Collection {
			alltemplates = append(alltemplates, t)
		}

		next_link := templates.GetNext()
		templates_raw, err = c.SetHeader("Accept", "application/vnd.abiquo.virtualmachinetemplates+json").
			Get(next_link.Href)
		if err != nil {
			return vt, err
		}
		json.Unmarshal(templates_raw.Body(), &templates)
	}

	for _, t := range alltemplates {
		if t.Name == template_name {
			return t, nil
		}
	}
	errorMsg := fmt.Sprintf("Template '%s' not found in VDC '%s'", template_name, v.Name)
	return vt, errors.New(errorMsg)
}

func (v *VDC) HardwareProfiles(c *resty.Request) ([]HWprofile, error) {
	var profiles []HWprofile
	var dto DTO
	var hwp HWprofile

	lims_raw, err := v.FollowLink("limit", c)
	if err != nil {
		return profiles, err
	}
	json.Unmarshal(lims_raw.Body(), &dto)

	for _, l := range dto.Links {
		resp, err := l.Get(c)
		if err != nil {
			return profiles, err
		}
		json.Unmarshal(resp.Body(), &hwp)
		profiles = append(profiles, hwp)
	}
	return profiles, nil
}

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

func (l *Limit) GetHardwareProfiles(c *resty.Request) ([]HWprofile, error) {
	var allProfiles []HWprofile
	if !l.EnabledHardwareProfiles {
		return allProfiles, nil
	}

	for _, link := range l.Links {
		if link.Rel == "hardwareprofile" {
			var hp HWprofile
			hp_raw, err := c.SetHeader("Accept", link.Type).
				Get(link.Href)
			if err != nil {
				return allProfiles, err
			}
			json.Unmarshal(hp_raw.Body(), &hp)
			allProfiles = append(allProfiles, hp)
		}
	}
	return allProfiles, nil
}

type VirtualMachineCollection struct {
	AbstractCollection
	Collection []VirtualMachine
}

type VirtualMachine struct {
	DTO
	UUID              string                 `json:"uuid,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Label             string                 `json:"label,omitempty"`
	Description       string                 `json:"description,omitempty"`
	CPU               int                    `json:"cpu,omitempty"`
	RAM               int                    `json:"ram,omitempty"`
	VdrpEnabled       bool                   `json:"vdrpEnabled,omitempty"`
	VdrpPort          int                    `json:"vdrpPort,omitempty"`
	IDState           int                    `json:"idState,omitempty"`
	State             string                 `json:"state,omitempty"`
	IDType            int                    `json:"idType,omitempty"`
	Type              string                 `json:"type,omitempty"`
	HighDisponibility int                    `json:"highDisponibility,omitempty"`
	Password          string                 `json:"password,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	Monitored         bool                   `json:"monitored,omitempty"`
	Protected         bool                   `json:"protected,omitempty"`
	Variables         map[string]string      `json:"variables,omitempty"`
	CreationTimestamp int64                  `json:"creationTimestamp,omitempty"`
	Backuppolicies    []interface{}          `json:"backuppolicies,omitempty"`
	LastSynchronize   int64                  `json:"lastSynchronize,omitempty"`
}

func (v *VirtualMachine) GetVapp(c *resty.Request) (VirtualApp, error) {
	var vapp VirtualApp
	vapp_raw, err := v.FollowLink("virtualappliance", c)
	if err != nil {
		return vapp, err
	}
	json.Unmarshal(vapp_raw.Body(), &vapp)
	return vapp, nil
}

func (v *VirtualMachine) Deploy(c *resty.Request) error {
	deploy_lnk, err := v.GetLink("deploy")
	accept_request_raw, err := c.SetHeader("Accept", "application/vnd.abiquo.acceptedrequest+json").
		Post(deploy_lnk.Href)
	if err != nil {
		return err
	}
	var accept_request AcceptedRequest
	json.Unmarshal(accept_request_raw.Body(), &accept_request)

	for {
		vm_raw, err := v.Refresh(c)
		if err != nil {
			return err
		}
		json.Unmarshal(vm_raw.Body(), v)
		if v.State == "LOCKED" {
			time.Sleep(10 * time.Second)
		} else {
			break
		}
	}

	task_lnk, _ := accept_request.GetLink("status")
	task_raw, err := c.SetHeader("Accept", "application/vnd.abiquo.taskextended+json").
		Get(task_lnk.Href)
	if err != nil {
		return err
	}
	var task Task
	json.Unmarshal(task_raw.Body(), &task)
	if task.State != "FINISHED_SUCCESSFULLY" {
		errorMsg := fmt.Sprintf("Task to deploy VM %s failed. Check events.", v.Name)
		return errors.New(errorMsg)
	}
	return nil
}

func (v *VirtualMachine) PowerOn(c *resty.Request) error {
	return v.applyState("ON", c)
}

func (v *VirtualMachine) PowerOff(c *resty.Request) error {
	return v.applyState("OFF", c)
}

func (v *VirtualMachine) applyState(state string, c *resty.Request) error {
	body := fmt.Sprintf("{\"state\": \"%s\"}", state)
	state_lnk, _ := v.GetLink("state")
	accept_request_raw, err := c.SetHeader("Accept", "application/vnd.abiquo.acceptedrequest+json").
		SetHeader("Content-Type", "application/vnd.abiquo.virtualmachinestate+json").
		SetBody(body).
		Put(state_lnk.Href)
	if err != nil {
		return err
	}
	var accept_request AcceptedRequest
	json.Unmarshal(accept_request_raw.Body(), &accept_request)

	for {
		vm_raw, err := v.Refresh(c)
		if err != nil {
			return err
		}
		json.Unmarshal(vm_raw.Body(), v)
		if v.State == "LOCKED" {
			time.Sleep(10 * time.Second)
		} else {
			break
		}
	}

	task_lnk, _ := accept_request.GetLink("status")
	task_raw, err := c.SetHeader("Accept", "application/vnd.abiquo.taskextended+json").
		Get(task_lnk.Href)
	if err != nil {
		return err
	}
	var task Task
	json.Unmarshal(task_raw.Body(), &task)
	if task.State != "FINISHED_SUCCESSFULLY" {
		errorMsg := fmt.Sprintf("Task to power %s VM %s failed. Check events.", state, v.Name)
		return errors.New(errorMsg)
	}
	return nil
}

func (v *VirtualMachine) Reset(c *resty.Request) error {
	body := ""
	reset_lnk, _ := v.GetLink("reset")
	accept_request_raw, err := c.SetHeader("Accept", "application/vnd.abiquo.acceptedrequest+json").
		SetHeader("Content-Type", "application/vnd.abiquo.virtualmachinestate+json").
		SetBody(body).
		Post(reset_lnk.Href)
	if err != nil {
		return err
	}
	var accept_request AcceptedRequest
	json.Unmarshal(accept_request_raw.Body(), &accept_request)

	for {
		vm_raw, err := v.Refresh(c)
		if err != nil {
			return err
		}
		json.Unmarshal(vm_raw.Body(), v)
		if v.State == "LOCKED" {
			time.Sleep(10 * time.Second)
		} else {
			break
		}
	}

	task_lnk, _ := accept_request.GetLink("status")
	task_raw, err := c.SetHeader("Accept", "application/vnd.abiquo.taskextended+json").
		Get(task_lnk.Href)
	if err != nil {
		return err
	}
	var task Task
	json.Unmarshal(task_raw.Body(), &task)
	if task.State != "FINISHED_SUCCESSFULLY" {
		errorMsg := fmt.Sprintf("Task to reset VM %s failed. Check events.", v.Name)
		return errors.New(errorMsg)
	}
	return nil
}

func (v *VirtualMachine) Delete(c *resty.Request) error {
	edit_lnk, _ := v.GetLink("edit")
	_, err := c.Delete(edit_lnk.Href)
	if err != nil {
		return err
	}

	for {
		resp, err := v.Refresh(c)
		if err != nil {
			return err
		}
		if resp.StatusCode() == 404 {
			break
		}
		time.Sleep(10 * time.Second)
	}

	return nil
}

func (v *VirtualMachine) GetIP() string {
	var nics []Link
	for _, l := range v.Links {
		if strings.HasPrefix(l.Rel, "nic") {
			nics = append(nics, l)
		}
	}

	// First external ips
	for _, n := range nics {
		if n.Type == "application/vnd.abiquo.externalip+json" {
			return n.Title
		}
	}
	// Then public
	for _, n := range nics {
		if n.Type == "application/vnd.abiquo.publicip+json" {
			return n.Title
		}
	}
	// And private
	for _, n := range nics {
		if n.Type == "application/vnd.abiquo.privateip+json" {
			return n.Title
		}
	}
	return ""
}

type AcceptedRequest struct {
	DTO
	Message string `json:"message,omitempty"`
}

type Task struct {
	DTO
	JobsExtended struct {
		DTO
		Collection []struct {
			Links         []interface{} `json:"links,omitempty"`
			ID            string        `json:"id,omitempty"`
			ParentTaskID  string        `json:"parentTaskId,omitempty"`
			Type          string        `json:"type,omitempty"`
			Description   string        `json:"description,omitempty"`
			State         string        `json:"state,omitempty"`
			RollbackState string        `json:"rollbackState,omitempty"`
			Timestamp     int           `json:"timestamp,omitempty"`
		} `json:"collection,omitempty"`
	} `json:"jobsExtended,omitempty"`
	TaskID    string `json:"taskId,omitempty"`
	UserID    string `json:"userId,omitempty"`
	Type      string `json:"type,omitempty"`
	OwnerID   string `json:"ownerId,omitempty"`
	State     string `json:"state,omitempty"`
	Timestamp int    `json:"timestamp,omitempty"`
}

// type RequestOptions struct {
// 	Headers map[string]string
// }

// type Client struct {
// 	ApiUrl            string
// 	Insecure          bool
// 	ApiUser           string
// 	ApiPass           string
// 	AppKey            string
// 	AppSecret         string
// 	AccessToken       string
// 	AccessTokenSecret string

// 	httpClient http.Client
// }

// func (c *Client) Get(url string, opts RequestOptions) (*http.Response, error) {
// 	req := http.NewRequest("GET", url)

// 	for k, v := range opts.Headers {
// 		req.Header.Add(k, v)
// 	}
// }
