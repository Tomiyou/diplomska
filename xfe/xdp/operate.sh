#!/bin/bash

IFNAME=enx000ec669d86c

if [ "$1" == "load" ]; then
    sudo ip link set dev "$IFNAME" xdp pinned /sys/fs/bpf/xfe/xfe_ingress
elif [ "$1" == "reload" ]; then
    ip link set dev "$IFNAME" xdp off
    sudo ip link set dev "$IFNAME" xdp pinned /sys/fs/bpf/xfe/xfe_ingress
else
    ip link set dev "$IFNAME" xdp off
fi

ip a show "$IFNAME"
