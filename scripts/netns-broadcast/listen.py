# UDP listener: prints "<name> <port> <payload>" for every datagram.
import socket, sys, struct, select
name = sys.argv[1]
socks = []
for spec in sys.argv[2:]:
    port, _, group = spec.partition('@')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', int(port)))
    if group:
        g, _, ifaddr = group.partition('%')
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(g) + socket.inet_aton(ifaddr))
    socks.append((int(port), s))
print(name, 'ready', flush=True)
while True:
    r, _, _ = select.select([s for _, s in socks], [], [])
    for port, s in socks:
        if s in r:
            data, src = s.recvfrom(2048)
            print(name, port, data.decode(errors='replace'), 'from', src[0], flush=True)
