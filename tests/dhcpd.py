#!/usr/bin/env python3
# Tiny DHCP server for the tests: hands out one address on one interface.
# Usage: dhcpd.py IFACE ADDR ROUTER
import socket, struct, sys
iface, addr, router = sys.argv[1:4]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
s.bind(("0.0.0.0", 67))
while True:
    p, _ = s.recvfrom(1500)
    if len(p) < 240 or p[0] != 1:
        continue
    opts, i, kind = p[240:], 0, 0
    while i < len(opts) and opts[i] != 255:
        if opts[i] == 0:
            i += 1; continue
        if opts[i] == 53:
            kind = opts[i + 2]
        i += 2 + opts[i + 1]
    reply = {1: 2, 3: 5}.get(kind)
    if not reply:
        continue
    out = bytearray(p[:236])
    out[0] = 2
    out[16:20] = socket.inet_aton(addr)
    out[20:24] = socket.inet_aton(router)
    out += bytes([99, 130, 83, 99, 53, 1, reply, 54, 4]) + socket.inet_aton(router)
    out += bytes([1, 4, 255, 255, 255, 0, 3, 4]) + socket.inet_aton(router)
    out += bytes([51, 4]) + struct.pack("!I", 3600) + bytes([255])
    s.sendto(bytes(out), ("255.255.255.255", 68))
    print("dhcp", {2: "offer", 5: "ack"}[reply], addr, flush=True)
