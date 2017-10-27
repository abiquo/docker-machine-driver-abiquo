package abiquo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"

	"github.com/abiquo/docker-machine-driver-abiquo/abiquo"
)

const (
	driverName = "abiquo"
	dockerPort = 2376
	swarmPort  = 3376
)

type configError struct {
	option string
}

func (e *configError) Error() string {
	return fmt.Sprintf("abiquo driver requires the --abiquo-%s option", e.option)
}

type Driver struct {
	*drivers.BaseDriver
	Id       string
	ApiURL   string
	Insecure bool

	ApiUser           string
	ApiPass           string
	AppKey            string
	AppSecret         string
	AccessToken       string
	AccessTokenSecret string

	TemplateName      string
	VirtualDatacenter string
	VirtualAppliance  string
	NetworkName       string
	PublicIp          bool
	Cpus              int
	Ram               int
	HardwareProfile   string
	UserData          string
	Debug             bool
	DebugLogFile      string
}

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "abiquo-api-url",
			Usage:  "Abiquo API URL",
			EnvVar: "ABIQUO_API_URL",
		},
		mcnflag.BoolFlag{
			Name:   "abiquo-api-insecure",
			Usage:  "Abiquo API SSL verification",
			EnvVar: "ABIQUO_API_INSECURE",
		},
		mcnflag.StringFlag{
			Name:   "abiquo-api-username",
			Usage:  "Abiquo API username",
			EnvVar: "ABIQUO_API_USERNAME",
		},
		mcnflag.StringFlag{
			Name:   "abiquo-api-password",
			Usage:  "Abiquo API password",
			EnvVar: "ABIQUO_API_PASSWORD",
		},
		mcnflag.StringFlag{
			Name:   "abiquo-app-key",
			Usage:  "Abiquo API OAuth app key",
			EnvVar: "ABIQUO_API_APP_KEY",
		},
		mcnflag.StringFlag{
			Name:   "abiquo-app-secret",
			Usage:  "Abiquo API OAuth app secret",
			EnvVar: "ABIQUO_API_APP_SECRET",
		},
		mcnflag.StringFlag{
			Name:   "abiquo-access-token",
			Usage:  "Abiquo API OAuth access token",
			EnvVar: "ABIQUO_API_ACCESS_TOKEN",
		},
		mcnflag.StringFlag{
			Name:   "abiquo-access-token-secret",
			Usage:  "Abiquo API OAuth access token",
			EnvVar: "ABIQUO_API_ACCESS_TOKEN_SECRET",
		},
		mcnflag.StringFlag{
			Name:  "abiquo-template-name",
			Usage: "Template name",
		},
		mcnflag.StringFlag{
			Name:  "abiquo-vdc",
			Usage: "Abiquo VirtualDatacenter",
		},
		mcnflag.StringFlag{
			Name:  "abiquo-vapp",
			Usage: "Abiquo Virtualappliance",
			Value: "Docker Machine",
		},
		mcnflag.StringFlag{
			Name:  "abiquo-network",
			Usage: "Abiquo Network name",
			Value: "",
		},
		mcnflag.BoolFlag{
			Name:  "abiquo-public-ip",
			Usage: "Attach a public IP to the VM.",
		},
		mcnflag.IntFlag{
			Name:  "abiquo-cpus",
			Usage: "CPUs for the VM",
			Value: 1,
		},
		mcnflag.IntFlag{
			Name:  "abiquo-ram",
			Usage: "RAM in MB for the VM",
			Value: 1024,
		},
		mcnflag.StringFlag{
			Name:  "abiquo-hwprofile",
			Usage: "Hardware profile for the VM",
		},
		mcnflag.StringFlag{
			Name:  "abiquo-ssh-key",
			Usage: "Path to the SSH key file to use for SSH access",
		},
		mcnflag.StringFlag{
			Name:  "abiquo-ssh-user",
			Usage: "User name for SSH access",
		},
		mcnflag.StringFlag{
			Name:  "abiquo-user-data",
			Usage: "User Data to inject to VM",
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {
	driver := &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
		// FirewallRuleIds: []string{},
	}
	return driver
}

// DriverName returns the name of the driver as it is registered
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		template, err := d.getTemplate()
		if err != nil {
			return "root"
		}
		return template.LoginUser
	}
	return d.SSHUser
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.ApiURL = flags.String("abiquo-api-url")
	d.Insecure = flags.Bool("abiquo-api-insecure")
	d.ApiUser = flags.String("abiquo-api-username")
	d.ApiPass = flags.String("abiquo-api-password")
	d.AppKey = flags.String("abiquo-app-key")
	d.AppSecret = flags.String("abiquo-app-secret")
	d.AccessToken = flags.String("abiquo-access-token")
	d.AccessTokenSecret = flags.String("abiquo-access-token-secret")

	d.VirtualDatacenter = flags.String("abiquo-vdc")
	d.VirtualAppliance = flags.String("abiquo-vapp")
	d.NetworkName = flags.String("abiquo-network")
	d.PublicIp = flags.Bool("abiquo-public-ip")
	d.TemplateName = flags.String("abiquo-template-name")
	d.Cpus = flags.Int("abiquo-cpus")
	d.Ram = flags.Int("abiquo-ram")
	d.HardwareProfile = flags.String("abiquo-hwprofile")
	d.SSHKeyPath = flags.String("abiquo-ssh-key")
	d.SSHUser = flags.String("abiquo-ssh-user")
	d.UserData = flags.String("abiquo-user-data")

	d.SetSwarmConfigFromFlags(flags)

	if d.ApiURL == "" {
		return &configError{option: "api-url"}
	}

	if d.ApiUser == "" && d.AppKey == "" {
		return &configError{option: "api-username"}
	}

	if d.ApiUser != "" && d.ApiPass == "" {
		return &configError{option: "api-password"}
	}

	if d.TemplateName == "" {
		return &configError{option: "template-name"}
	}

	log.Debugf("App Key: '%s'", d.AppKey)
	log.Debugf("App Secret: '%s'", d.AppSecret)
	log.Debugf("Access Token: '%s'", d.AccessToken)
	log.Debugf("Access Token secret: '%s'", d.AccessTokenSecret)

	return nil
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:%d", ip, dockerPort), nil
}

// GetIP returns the IP that this host is available at
func (d *Driver) GetIP() (string, error) {
	if d.IPAddress == "" {
		vm, err := d.getVmByUrl(d.Id)
		if err != nil {
			return "", err
		}
		d.IPAddress = vm.GetIP()
	}
	return d.IPAddress, nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	vm, err := d.getVmByUrl(d.Id)
	if err != nil {
		return state.Error, err
	}

	switch vm.State {
	case "ON":
		return state.Running, nil
	case "OFF":
		return state.Stopped, nil
	case "NOT_ALLOCATED":
		return state.None, nil
	}

	return state.None, nil
}

// PreCreate allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	vdc, err := d.getVdc()
	log.Debug("Got VDC : ", vdc.Name)
	if err != nil {
		return err
	}

	var template_names []string
	templates, err := d.getVdcTemplates(vdc)
	if err != nil {
		return err
	}
	for _, t := range templates {
		template_names = append(template_names, t.Name)
	}
	log.Debug("Templates:", strings.Join(template_names, " "))

	_, err = d.getTemplate()
	if err != nil {
		return err
	}

	if err := d.checkCpuRam(); err != nil {
		return err
	}

	return nil
}

// Create a host using the driver's config
func (d *Driver) Create() error {
	var dockerVM abiquo_api.VirtualMachine
	dockerVM.Label = d.MachineName

	abq := d.getClient()

	// Get VDC
	vdc, err := d.getVdc()
	if err != nil {
		return err
	}
	edit, _ := vdc.GetLink("edit")
	log.Debug("Got VDC:", edit.Href)

	// Get vApp
	vapp, err := d.createOrGetVapp()
	if err != nil {
		return err
	}
	edit, _ = vapp.GetLink("edit")
	log.Debug("Got vApp:", edit.Href)

	// Get Template
	template, err := d.getTemplate()
	if err != nil {
		return err
	}
	template_lnk, _ := template.GetLink("edit")
	template_lnk.Rel = "virtualmachinetemplate"
	dockerVM.Links = append(dockerVM.Links, template_lnk)
	edit, _ = template.GetLink("edit")
	log.Debug("Got Template:", edit.Href)

	// If we need HP, look it up
	if d.HardwareProfile != "" {
		hprof, err := d.getHWProfile(vdc)
		if err != nil {
			return err
		}
		hp_lnk, _ := hprof.GetLink("self")
		hp_lnk.Rel = "hardwareprofile"
		dockerVM.Links = append(dockerVM.Links, hp_lnk)
		log.Debug("Got HW profile:", hp_lnk.Href)
	} else {
		dockerVM.CPU = d.Cpus
		dockerVM.RAM = d.Ram
		log.Debug(fmt.Sprintf("Set VM resoures, %d CPU, %d RAM", dockerVM.CPU, dockerVM.RAM))
	}

	// Set Network
	dockerVM, err = d.setVMNetwork(dockerVM)
	if err != nil {
		return err
	}

	// Create the machine
	log.Info("Creating virtual machine...")
	dockerVM, err = d.createVM(vapp, dockerVM)
	if err != nil {
		return err
	}

	vm_url, _ := dockerVM.GetLink("edit")
	d.Id = vm_url.Href
	log.Info(fmt.Sprintf("Created VM: %s (%s)", dockerVM.Name, d.Id))

	// Set user data
	log.Debug(fmt.Sprintf("Key Path is: %s", d.SSHKeyPath))
	if d.SSHKeyPath == "" {
		log.Info("Creating SSH key...")
		if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
			return err
		}
	}
	ssh_key_bytes, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}
	d.setUserData(dockerVM, ssh_key_bytes)
	log.Debug("Metadata updated")

	// Deploy
	log.Info(fmt.Sprintf("Deploying VM %s", dockerVM.Name))
	err = dockerVM.Deploy(abq)
	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("Deployed VM %s successfully", dockerVM.Name))

	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	abq := d.getClient()
	vm, err := d.getVmByUrl(d.Id)
	if err != nil {
		return err
	}

	log.Info(fmt.Sprintf("Deleting VM %s...", vm.Name))
	err = vm.Delete(abq)
	if err != nil {
		if !strings.Contains(err.Error(), "404") {
			return err
		}
	}

	vapp, err := vm.GetVapp(abq)
	if err != nil {
		return err
	}

	vms, err := vapp.GetVMs(abq)
	if err != nil {
		return err
	}
	if len(vms) == 0 {
		log.Info("Deleting vApp since it's empty.")
		vapp.Delete(abq)
	}

	return nil
}

// Start a host
func (d *Driver) Start() error {
	vm, err := d.getVmByUrl(d.Id)
	if err != nil {
		return err
	}

	abq := d.getClient()
	err = vm.PowerOn(abq)
	if err != nil {
		return err
	}

	return nil
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	vm, err := d.getVmByUrl(d.Id)
	if err != nil {
		return err
	}

	abq := d.getClient()
	err = vm.PowerOff(abq)
	if err != nil {
		return err
	}

	return nil
}

// Restart a host.
func (d *Driver) Restart() error {
	vm, err := d.getVmByUrl(d.Id)
	if err != nil {
		return err
	}

	abq := d.getClient()
	err = vm.Reset(abq)
	if err != nil {
		return err
	}

	return nil
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	return d.Stop()
	return nil
}

func (d *Driver) checkCpuRam() error {
	abq := d.getClient()
	vdc, err := d.getVdc()
	if err != nil {
		return err
	}

	var lim abiquo_api.Limit
	lim_raw, _ := vdc.FollowLink("limit", abq)
	json.Unmarshal(lim_raw.Body(), &lim)

	if lim.EnabledHardwareProfiles {
		// Ned a HW profile
		hwprofiles, err := vdc.GetHardwareProfiles(abq)
		if err != nil {
			return err
		}
		for _, hp := range hwprofiles {
			if hp.Name == d.HardwareProfile {
				return nil
			}
		}
		errorMsg := fmt.Sprintf("Hardware Profile '%s' not found.", d.HardwareProfile)
		return errors.New(errorMsg)
	}
	return nil
}

func (d *Driver) getTemplate() (abiquo_api.VirtualMachineTemplate, error) {
	var template abiquo_api.VirtualMachineTemplate
	abq := d.getClient()
	vdc, err := d.getVdc()
	if err != nil {
		return template, err
	}
	template, err = vdc.GetTemplate(d.TemplateName, abq)
	if err != nil {
		return template, err
	}
	return template, nil
}

func (d *Driver) getVdcTemplates(vdc abiquo_api.VDC) ([]abiquo_api.VirtualMachineTemplate, error) {
	var alltemplates []abiquo_api.VirtualMachineTemplate

	abq := d.getClient()
	alltemplates, err := vdc.GetTemplates(abq)
	if err != nil {
		return alltemplates, err
	}

	return alltemplates, nil
}

func (d *Driver) getVdc() (abiquo_api.VDC, error) {
	var novdc abiquo_api.VDC
	vdcs, err := d.getVdcs()
	if err != nil {
		return novdc, err
	}

	for _, vdc := range vdcs {
		if vdc.Name == d.VirtualDatacenter {
			return vdc, nil
		}
	}

	errorMsg := fmt.Sprintf("VDC '%s' does not exist.", d.VirtualDatacenter)
	return novdc, errors.New(errorMsg)
}

func (d *Driver) getVdcs() ([]abiquo_api.VDC, error) {
	var allVdcs []abiquo_api.VDC

	abq := d.getClient()
	allVdcs, err := abq.GetVDCs()
	return allVdcs, err
}

func (d *Driver) createOrGetVapp() (abiquo_api.VirtualApp, error) {
	var vapp abiquo_api.VirtualApp
	abq := d.getClient()
	vdc, err := d.getVdc()
	if err != nil {
		return vapp, err
	}

	vapps, err := vdc.GetVirtualApps(abq)
	if err != nil {
		return vapp, err
	}

	for _, vapp := range vapps {
		if vapp.Name == d.VirtualAppliance {
			return vapp, nil
		}
	}

	vapp, err = d.createVapp()
	if err != nil {
		return vapp, err
	}
	return vapp, nil
}

func (d *Driver) createVapp() (abiquo_api.VirtualApp, error) {
	var vapp abiquo_api.VirtualApp
	abq := d.getClient()
	vdc, err := d.getVdc()
	if err != nil {
		return vapp, err
	}

	vapp, err = vdc.CreateVapp(d.VirtualAppliance, abq)
	if err != nil {
		return vapp, err
	}
	return vapp, nil
}

func (d *Driver) getVmByUrl(vmurl string) (abiquo_api.VirtualMachine, error) {
	var vm abiquo_api.VirtualMachine

	if vmurl != "" {
		fragments := strings.Split(vmurl, "/")
		vm_id := fragments[len(fragments)-1]
		_, err := strconv.ParseInt(vm_id, 10, 64)
		if err != nil {
			return vm, err
		}

		abq := d.getClient()
		vm, err = abq.GetVMByUrl(vmurl)
		if err != nil {
			return vm, err
		}
		return vm, nil
	} else {
		errorMsg := "VM url is empty."
		return vm, errors.New(errorMsg)
	}
}

func (d *Driver) getHWProfile(vdc abiquo_api.VDC) (abiquo_api.HWprofile, error) {
	var hwprofile abiquo_api.HWprofile
	var lim abiquo_api.Limit
	abq := d.getClient()
	lim_raw, err := vdc.FollowLink("limit", abq)
	if err != nil {
		return hwprofile, err
	}
	json.Unmarshal(lim_raw.Body(), &lim)
	hprofiles, err := vdc.GetHardwareProfiles(abq)
	if err != nil {
		return hwprofile, err
	}
	for _, hprof := range hprofiles {
		log.Debug(fmt.Sprintf("Found HW profile with name '%s'", hprof.Name))
		if hprof.Name == d.HardwareProfile {
			hwprofile = hprof
		}
	}
	return hwprofile, nil
}

func (d *Driver) createVM(vapp abiquo_api.VirtualApp, vm abiquo_api.VirtualMachine) (abiquo_api.VirtualMachine, error) {
	var vm_created abiquo_api.VirtualMachine
	abq := d.getClient()

	p, err := abq.GetConfigProperty("client.virtual.allowVMRemoteAccess")
	if err != nil {
		log.Debug("Could not check if remote access is enabled. Will keep it disabled.")
	}
	log.Debug(fmt.Sprintf("Got config properties '%s' with value '%s'", p.Name, p.Value))
	if p.Value == "1" {
		log.Debug("Enabling remote access.")
		vm.VdrpEnabled = true
	}
	body, _ := json.Marshal(vm)

	log.Debugf("VM JSON : %s", body)
	vm_created, err = vapp.CreateVM(vm, abq)
	if err != nil {
		return vm_created, err
	}
	return vm_created, nil
}

func (d *Driver) setVMNetwork(vm abiquo_api.VirtualMachine) (abiquo_api.VirtualMachine, error) {
	abq := d.getClient()
	vdc, err := d.getVdc()
	if err != nil {
		return vm, err
	}

	if d.PublicIp {
		// Public IP requested
		var ip abiquo_api.Ip

		if vdc.IsPCR() {
			// Allocate floating IP
			ip, err = vdc.AllocateFloatingIp(abq)
			if err != nil {
				return vm, err
			}
		} else {
			// Allocate public IP
			ip, err = vdc.AllocatePublicIp(abq, d.NetworkName)
			if err != nil {
				return vm, err
			}
		}

		ip_link, _ := ip.GetLink("self")
		ip_link.Rel = "nic0"
		vm.Links = append(vm.Links, ip_link)
	} else {
		// No public IP
		// Allocate to specified net if defined
		// Otherwise, let Abiquo use default network
		if d.NetworkName != "" {
			var net abiquo_api.Vlan

			nets, err := vdc.GetNetworks(abq)
			if err != nil {
				return vm, err
			}

			for _, n := range nets {
				if n.Name == d.NetworkName {
					net = n
				}
			}
			ip, err := net.GetFreeIp(abq)
			if err != nil {
				return vm, err
			}

			ip_link, _ := ip.GetLink("self")
			ip_link.Rel = "nic0"
			vm.Links = append(vm.Links, ip_link)
		}
	}

	return vm, nil
}

func (d *Driver) setUserData(vm abiquo_api.VirtualMachine, ssh_key_bytes []byte) error {
	abq := d.getClient()
	mdata := fmt.Sprintf("#cloud-config\nusers:\n  - default:\n    ssh-authorized-keys:\n      - %s", ssh_key_bytes)
	log.Debug(fmt.Sprintf("Generated cloud-init script is: %s", mdata))

	if d.UserData != "" {
		mdata = d.UserData
	}
	links := []int{}
	md := make(map[string]interface{})
	md2 := make(map[string]interface{})
	md2["startup-script"] = mdata
	md["links"] = links
	md["metadata"] = md2

	body, _ := json.Marshal(md)
	log.Debug("Metadata will be:", fmt.Sprintf("%s", body))
	err := vm.SetMetadata(fmt.Sprintf("%s", body), abq)
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) getClient() *abiquo_api.AbiquoClient {
	if d.AppKey != "" {
		return abiquo_api.GetOAuthClient(d.ApiURL, d.AppKey, d.AppSecret, d.AccessToken, d.AccessTokenSecret, d.Insecure)
	} else if d.ApiUser != "" {
		return abiquo_api.GetClient(d.ApiURL, d.ApiUser, d.ApiPass, d.Insecure)
	}
	return nil
}
