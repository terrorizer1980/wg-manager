# wg-manager

## Introduction

This tool is used on our server side infrastructure to manage Wireguard interfaces for our customers. This is not designed to be used by customers.

wg-manager runs as a service on our infrastructure to enable users to connect and use our Wireguard servers.

This services performs a number of tasks such as:

- Keeping track and syncing the public key and peer data from our API
- Removing and re-adding peers that were connected and subsequently disconnected, zeroing out information about when a peer was last connected.
- Managing IPTable (firewall) rules for portforwarding
- Gathering metrics about our Wireguard servers

This project is not affiliated with the WireGuard project.
WireGuard is a registered trademark of Jason A. Donenfeld.

## Building

Clone this repository, and run `make` to build.
This will produce a `wg-manager` binary and put them in your `GOBIN`.

## Testing

There are three ways to run tests:

1. To run tests which do not depend on wireguard or iptables, run `make test`.
1. To run integrations tests which requires wireguard and iptables, run `make integration-test`.
1. To run continuous testing in docker, run `make docker-test`.
   This requires wireguard to be setup on the host machine

### Testing iptables using network namespaces
To test iptables without messing with your system configuration, you can use network namespaces.
To set one up, enter it and allow localhost routing, run the following commands:

```
sudo ip netns add wg-test
sudo -E env "PATH=$PATH" nsenter --net=/var/run/netns/wg-test
ip link set up lo
./setup_testing_environment.sh
```

Then you can run the tests as described above.

### Testing iptables using docker
Run `make shell` to get a docker shell which has an isolated network.
It will drop you in the `/repo` folder which is mounted to the source.
You can then run `make integration-test` or any other make or go commands.

## Usage
All options can be either configured via command line flags, or via their respective environment variable, as denoted by `[ENVIRONMENT_VARIABLE]`.
To get a list of all the options, run `wg-manager -h`.

When installed via the `.deb` package, a user named `wireguard-manager` will be created for the service to run as, as well as a systemd service named `wireguard-manager.service`.
The name of the binary when installed via the `.deb` package is `wireguard-manager`.
Configuration is done by creating a file at `/etc/default/wireguard-manager` and defining the environment variables there.
All logs are sent to stdout/stderr, so in order to debug issues with the service, simply use `journalctl` or `systemctl status`.

## Packaging
In order to deploy wg-manager, we build `.deb` packages. We use docker to make this process easier, so make sure you have that installed and running.
To create a new package, first create a new tag in git, this will be used for the package version:
```
git tag -s -a v1.0.0 -m "1.0.0"
```
Then, run `make package`. This will output the new package in the `build` folder.
Don't forget to push the tag to git afterwards.
