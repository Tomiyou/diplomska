#!/bin/bash

CUR_DIR=$(pwd)
BASE_DIR=$(dirname "$CUR_DIR")

# Export ENV variables
export LD_LIBRARY_PATH=${BASE_DIR}/linux/tools/lib/bpf:$LD_LIBRARY_PATH
export XFE_OBJ_PATH=${BASE_DIR}/xfe/xdp/xdp_pospesevalnik.o

# If BPF filesystem isn't mounted yet, do it now
if [[ ! -d /sys/fs/bpf/xfe ]]; then
    echo "Mounting BPF filesystem"
    mount -t bpf none /sys/fs/bpf
    mkdir -p /sys/fs/bpf/xfe
fi

# Run xfe_ctl app and pass all arguments to it
${BASE_DIR}/xfe/app/xfe_ctl "$@"
