#!/bin/bash
# Broadcast delivery/forwarding matrix on a Linux host with IP forwarding,
# without root: each run is a fresh user + network namespace (the "Core
# host": msst0 TUN 172.22.0.1/16, veth0 192.168.1.1/24 + 10.0.0.1/16) with
# a LAN host behind it (192.168.1.2/24, 10.0.0.255/16).  Packets from a
# member's address (172.22.0.7) are written into msst0, as Core injects
# them; the output lists who received each and what came back out of the
# TUN.  See docs/SECURITY_3.1.6.md.
cd "$(dirname "$0")"
for v in "0 0 0" "1 0 0" "2 0 0" "0 1 1" "0 1 0"; do
    set -- $v
    RP=$1 BCF=$2 BCF_MSST=$3 unshare -rn ./run.sh 2>&1 | grep -v '^$'
    echo
done
