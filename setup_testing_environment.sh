#! /bin/sh

# Add wireguard interfaces.
ip link add wg0 type wireguard
ip link add wg1 type wireguard
ip link set up wg0
ip link set up wg1

# Set up peer addresses for the interfaces.
ip address add dev wg0 10.99.0.1 peer 10.99.0.2
ip address add dev wg1 10.99.0.2 peer 10.99.0.1

# Set up iptables.
iptables -t nat -N PORTFORWARDING_TCP
ip6tables -t nat -N PORTFORWARDING_TCP
iptables -t nat -N PORTFORWARDING_UDP
ip6tables -t nat -N PORTFORWARDING_UDP
ipset create PORTFORWARDING_IPV4 hash:ip
ipset create PORTFORWARDING_IPV6 hash:ip family inet6
