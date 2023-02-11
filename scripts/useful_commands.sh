#!/bin/bash

mknod /dev/sfe_debug c 243 0







# CPU frequency scaling
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

cpufreq-set -c 0 --governor userspace
cpufreq-set -c 1 --governor userspace
cpufreq-set -c 2 --governor userspace
cpufreq-set -c 3 --governor userspace

sleep 3

cpufreq-set -c 0 --freq 1600000
cpufreq-set -c 1 --freq 1600000
cpufreq-set -c 2 --freq 1600000
cpufreq-set -c 3 --freq 1600000

cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Reset CPU governor
cpufreq-set -c 0 --governor ondemand
cpufreq-set -c 1 --governor ondemand
cpufreq-set -c 2 --governor ondemand
cpufreq-set -c 3 --governor ondemand




# IRQ affinity

# 4 cores
# enp1s0f0
echo 8 > /proc/irq/29/smp_affinity
echo 1 > /proc/irq/30/smp_affinity
echo 2 > /proc/irq/31/smp_affinity
echo 4 > /proc/irq/32/smp_affinity
# enp2s0f0
echo 8 > /proc/irq/39/smp_affinity
echo 1 > /proc/irq/40/smp_affinity
echo 2 > /proc/irq/41/smp_affinity
echo 4 > /proc/irq/42/smp_affinity

# 2 cores
# enp1s0f0
echo 1 > /proc/irq/29/smp_affinity
echo 1 > /proc/irq/30/smp_affinity
echo 2 > /proc/irq/31/smp_affinity
echo 2 > /proc/irq/32/smp_affinity
# enp2s0f0
echo 1 > /proc/irq/39/smp_affinity
echo 1 > /proc/irq/40/smp_affinity
echo 2 > /proc/irq/41/smp_affinity
echo 2 > /proc/irq/42/smp_affinity


# Print values
echo "enp1s0f0 affinity"
cat /proc/irq/29/smp_affinity
cat /proc/irq/30/smp_affinity
cat /proc/irq/31/smp_affinity
cat /proc/irq/32/smp_affinity
cat /proc/irq/33/smp_affinity
echo "enp2s0f0 affinity"
cat /proc/irq/39/smp_affinity
cat /proc/irq/40/smp_affinity
cat /proc/irq/41/smp_affinity
cat /proc/irq/42/smp_affinity
cat /proc/irq/43/smp_affinity
