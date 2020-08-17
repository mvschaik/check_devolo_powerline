# Icinga/Nagios check for Devolo Powerline DLAN adapters

This is a check that can read out some information from Devolo DLAN adapters.
It's created by reverse engineering the Web UI of the devices.

I've tested on the following devices:
* Devolo Magic 2 LAN 1-1 with firmware 7.8.5.47 (2020-06-05)
* Devolo Magic 2 WiFi next with firmware 5.4.0 (2020-01-29)

These devices have a different Web interface, so using the Magic 2 LAN 1-1
requires passing the `--legacy` flag to the check.

## Installation instructions

I've only installed this on Debian/Raspbian Buster.

### Prerequisites

The check requires some Python packages to be available:

```sh
sudo apt install python3-nagiosplugin python3-request
```

### Installation

Make the check available in the Icinga/Nagios `PluginDir`.

```sh
sudo ln -s check_devolo_powerline.py /usr/lib/nagios/plugins/check_dlan
```

Test that Icinga can run it.

```sh
sudo -u nagios /usr/lib/nagios/plugins/check_dlan --help
```

Copy the configuration file `dlan.conf` to the /etc/icinga2/conf.d configuration
directory. This will add a `dlan` CheckCommand, a HostGroup for DLAN adapters
and apply the check to the group. You'll have to add the adapters to the group.

```
object Host "my-adapter" {
    address = "192.168....."
    groups = ["dlan-adapters"]
}
```

