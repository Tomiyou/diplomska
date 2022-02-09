#!/bin/bash -x
ip addr add 192.168.100.2/24 dev enx000ec669d86c
ip addr add 192.168.10.1/24 dev enx00e04c04063e
ip link set enx000ec669d86c up
ip link set enx00e04c04063e up
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -I POSTROUTING 1 -o enx000ec669d86c -j MASQUERADE
