#!/bin/bash -x

diplomska_host="brazzers_nuc"
host_home_dir="/home/flowfield/diplomska"
macbook="netops@192.168.64.150"
iperf_command="/usr/local/bin/iperf -c 192.168.100.1 -i1 -t60 -P4"

remote_sudo() {
    echo "$2" | ssh -tt "$1" "sudo bash -c '$3'"
}

disable_cpu_scaling() {
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 0 --governor userspace"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 1 --governor userspace"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 2 --governor userspace"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 3 --governor userspace"

    ssh "$diplomska_host" "cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"

    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 0 --freq 1600000"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 1 --freq 1600000"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 2 --freq 1600000"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 3 --freq 1600000"
}

enable_cpu_scaling() {
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 0 --governor ondemand"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 1 --governor ondemand"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 2 --governor ondemand"
    remote_sudo "$diplomska_host" "wersdf234" "cpufreq-set -c 3 --governor ondemand"

    ssh "$diplomska_host" "cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
}

run_test() {
    echo "################################# Starting $1 test #################################"
    ssh "$diplomska_host" "lsmod"

    # Run iperf server
    iperf -s -i1 > "logs/$1_$2core_iperf_server.log" &

    # Start mpstat CPU usage logging
    ssh "$diplomska_host" "mpstat -P ALL 2 40 > ~/logs/$1_$2core_mpstat.log" &
    echo "mpstat started"

    # Capture idle CPU for 10 seconds
    sleep 10

    # Start iperf client on macbook
    echo "Starting iperf client"
    ssh "$macbook" "$iperf_command > ~/Documents/diplomska/$1_$2core_iperf.log"
    echo "Test complete"

    # Stop iperf server
    killall iperf

    # Let mpstat process complete, cool down CPU
    sleep 40

    # Transfer captured logs locally and delete remote versions
    echo "Download captured logs"
    scp "$macbook:./Documents/diplomska/$1_$2core_iperf.log" ./logs/
    ssh "$macbook" "rm ~/Documents/diplomska/$1_$2core_iperf.log"

    scp "$diplomska_host:./logs/$1_$2core_mpstat.log" ./logs/
    ssh "$diplomska_host" "rm ~/logs/$1_$2core_mpstat.log"
}


# Disable frequency scaling
disable_cpu_scaling


# Pure Linux goes first
run_test "linux" "$1"



# SFE is next
remote_sudo "$diplomska_host" "wersdf234" "cd $host_home_dir/linux/net/shortcut-fe/; insmod shortcut-fe.ko; insmod shortcut-fe-cm.ko"

run_test "sfe" "$1"

remote_sudo "$diplomska_host" "wersdf234" "rmmod shortcut_fe_cm; rmmod shortcut_fe"



# And finally XFE
remote_sudo "$diplomska_host" "wersdf234" "cd $host_home_dir/scripts; insmod ../xfe/kmod/xfe.ko; ./xfe_ctrl.sh init; ./xfe_ctrl.sh attach enp1s0f0 enp2s0f0"
sleep 8

run_test "xdp" "$1"

remote_sudo "$diplomska_host" "wersdf234" "cd $host_home_dir/scripts; ./xfe_ctrl.sh deinit; rmmod xfe"


# Enable frequency scaling
enable_cpu_scaling
