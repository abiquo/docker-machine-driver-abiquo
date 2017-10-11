# Docker Machine Driver for Abiquo

This is a driver for [Docker Machine](https://docs.docker.com/machine/), enabling it to create Docker hosts on [Abiquo](https://www.abiquo.com/) based clouds.

## Requirements

* [Docker Machine](https://docs.docker.com/machine/). Tested with 0.12.2.

## Installation

Download the binary from follwing link and put it within your PATH (ex. `/usr/local/bin`)

https://github.com/abiquo/docker-machine-driver-abiquo/releases/latest

## Usage

Run `docker-machine create` without options to get the list of available parameters

```bash
$ docker-machine create -d abiquo
Usage: docker-machine create [OPTIONS] [arg...]

Create a machine

Description:
   Run 'docker-machine create --driver name' to include the create flags for that driver in the help text.

Options:

   --abiquo-access-token                    Abiquo API OAuth access token [$ABIQUO_API_ACCESS_TOKEN]
   --abiquo-access-token-secret                   Abiquo API OAuth access token [$ABIQUO_API_ACCESS_TOKEN_SECRET]
   --abiquo-api-insecure                    Abiquo API SSL verification [$ABIQUO_API_INSECURE]
   --abiquo-api-password                    Abiquo API password [$ABIQUO_API_PASSWORD]
   --abiquo-api-url                       Abiquo API URL [$ABIQUO_API_URL]
   --abiquo-api-username                    Abiquo API username [$ABIQUO_API_USERNAME]
   --abiquo-app-key                       Abiquo API OAuth app key [$ABIQUO_API_APP_KEY]
   --abiquo-app-secret                      Abiquo API OAuth app secret [$ABIQUO_API_APP_SECRET]
   --abiquo-cpus "1"                      CPUs for the VM
   --abiquo-debug                     Wether or not to output debug logging for the Abiquo API calls
   --abiquo-debug-log-file "/tmp/docker-machine-driver-abiquo.log"          Log file where to output debug from HTTP client
   --abiquo-hwprofile                       Hardware profile for the VM
   --abiquo-ram "1024"                      RAM in MB for the VM
   --abiquo-ssh-key                       Path to the SSH key file to use for SSH access
   --abiquo-ssh-user                      User name for SSH access
   --abiquo-template-name                     Template name
   --abiquo-user-data                       User Data to inject to VM
   --abiquo-vapp "Docker Machine"                 Abiquo Virtualappliance
   --abiquo-vdc                       Abiquo VirtualDatacenter
```

# License and Authors

* Author:: Marc Cirauqui (marc.cirauqui@abiquo.com)

Copyright:: 2014, Abiquo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
