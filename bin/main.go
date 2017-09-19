package main

import (
	"github.com/abiquo/docker-machine-driver-abiquo"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(abiquo.NewDriver("", ""))
}
