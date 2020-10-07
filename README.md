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
To run the tests, run `make test`.

To run the integration tests as well, look at the `.travis`-file in the repository to see the prerequisite steps to be able to run them. After which you can run `go test ./...`. Note that this requires WireGuard to be running on the machine, and root privileges.

### Testing iptables using network namespaces
To test iptables without messing with your system configuration, you can use network namespaces.
To set one up, enter it and allow localhost routing, run the following commands:

```
sudo ip netns add wg-test
sudo -E env "PATH=$PATH" nsenter --net=/var/run/netns/wg-test
ip link set up lo
```

Then you can run the tests as described above.

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
