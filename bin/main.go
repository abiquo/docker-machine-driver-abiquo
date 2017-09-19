package main

import (
	"docker-machine-driver-abiquo"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(abiquo.NewDriver("", ""))
}
