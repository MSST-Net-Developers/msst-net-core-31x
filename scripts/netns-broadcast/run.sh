#!/bin/bash
# Runs inside `unshare -rn` (see matrix.sh).
# This netns is the Core host ("router").
set -e
D=$(dirname "$0")
ip link set lo up
ip tuntap add dev msst0 mode tun
ip addr add 172.22.0.1/16 dev msst0
ip link set msst0 up
# LAN host in its own netns.
unshare -n sleep 30 & H=$!
sleep 0.3
ip link add veth0 type veth peer name veth1
ip link set veth1 netns $H
ip addr add 192.168.1.1/24 dev veth0
ip addr add 10.0.0.1/16 dev veth0
ip link set veth0 up
nsenter -t $H -n sh -c 'ip link set lo up; ip addr add 192.168.1.2/24 dev veth1; ip addr add 10.0.0.255/16 dev veth1; ip link set veth1 up; ip route add default via 192.168.1.1'
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=${RP:-0} net.ipv4.conf.msst0.rp_filter=${RP:-0}
sysctl -qw net.ipv4.conf.all.bc_forwarding=${BCF:-0} net.ipv4.conf.veth0.bc_forwarding=${BCF:-0} net.ipv4.conf.msst0.bc_forwarding=${BCF_MSST:-${BCF:-0}}
OUT=$(mktemp)
python3 -u $D/listen.py core-host 4000 4445@224.0.2.60%172.22.0.1 >>$OUT 2>&1 &
nsenter -t $H -n python3 -u $D/listen.py lan-host 4000 4445@224.0.2.60%192.168.1.2 >>$OUT 2>&1 &
sleep 0.5
python3 -u $D/inject.py msst0 172.22.0.7 \
  msst-bcast:172.22.255.255:4000 limited-bcast:255.255.255.255:4000 \
  lan-directed-bcast:192.168.1.255:4000 lan-unicast:192.168.1.2:4000 \
  slash16-dot255:10.0.0.255:4000 mc-java:224.0.2.60:4445 msst-not-bcast:172.22.1.255:4000 >>$OUT
sleep 0.5
echo "## ip_forward=1 rp_filter=${RP:-0} bc_forwarding all/veth0=${BCF:-0} msst0=${BCF_MSST:-${BCF:-0}}"
grep -v ready $OUT | sort
kill %2 %3 $H 2>/dev/null || true
