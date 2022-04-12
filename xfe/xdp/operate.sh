#!/bin/bash

if [ "$1" == "load" ]; then
    ip link set dev "$2" xdp pinned /sys/fs/bpf/xfe/xfe_ingress
elif [ "$1" == "reload" ]; then
    ip link set dev "$2" xdp off
    ip link set dev "$2" xdp pinned /sys/fs/bpf/xfe/xfe_ingress
else
    ip link set dev "$2" xdp off
fi

ip a show "$2"
