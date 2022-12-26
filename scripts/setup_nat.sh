#!/bin/bash -x
ip addr add 192.168.100.2/24 dev enp1s0f0
ip addr add 192.168.10.1/24 dev enp2s0f0
ip link set enp1s0f0 up
ip link set enp2s0f0 up
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -I POSTROUTING 1 -o enp1s0f0 -j MASQUERADE
