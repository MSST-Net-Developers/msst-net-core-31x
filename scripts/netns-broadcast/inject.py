# Write IPv4/UDP packets into an existing TUN device: inject.py <tun> <src> <case>:<dst>:<port> ...
import fcntl, os, socket, struct, sys, time
TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454ca, 0x0001, 0x1000
fd = os.open('/dev/net/tun', os.O_RDWR)
fcntl.ioctl(fd, TUNSETIFF, struct.pack('16sH', sys.argv[1].encode(), IFF_TUN | IFF_NO_PI))
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff
src = socket.inet_aton(sys.argv[2])
for spec in sys.argv[3:]:
    case, dst, port = spec.split(':')
    payload = case.encode(); dst = socket.inet_aton(dst)
    udp = struct.pack('!HHHH', 5000, int(port), 8 + len(payload), 0) + payload
    c = csum(src + dst + struct.pack('!BBH', 0, 17, len(udp)) + udp) or 0xffff
    udp = udp[:6] + struct.pack('!H', c) + udp[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, src, dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    os.write(fd, h + udp)
    time.sleep(0.3)
    # Whatever the kernel sent back out of the TUN meanwhile.
    os.set_blocking(fd, False)
    while True:
        try:
            out = os.read(fd, 2048)
        except BlockingIOError:
            break
        if len(out) >= 28 and out[9] == 17:
            print('tun-out', out[28:].decode(errors='replace'), 'to', socket.inet_ntoa(out[16:20]), flush=True)
    os.set_blocking(fd, True)
