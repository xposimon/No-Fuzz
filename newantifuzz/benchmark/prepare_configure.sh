#!/bin/bash -x

echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first
echo core | sudo tee /proc/sys/kernel/core_pattern
# cd /sys/devices/system/cpu; echo performance | sudo tee cpu*/cpufreq/scaling_governor

sudo mkdir /usr/bin/afl-unix/
sudo chown `whoami`:`whoami` /usr/bin/afl-unix/
cp `which afl-fuzz` /usr/bin/afl-unix/

# Close ASLR for input-to-state analysis
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space