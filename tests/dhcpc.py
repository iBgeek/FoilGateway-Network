#!/usr/bin/env python3
# Bare DHCP client for the tests: asks on IFACE, puts the address on it and
# prints it, or prints "none" after SECS. Usage: dhcpc.py IFACE [SECS]
import socket, struct, subprocess, sys, time, os
iface = sys.argv[1]
secs = float(sys.argv[2]) if len(sys.argv) > 2 else 40
mac = bytes.fromhex(open(f"/sys/class/net/{iface}/address").read().strip().replace(":", ""))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
s.bind(("0.0.0.0", 68))
s.settimeout(2)

def pkt(kind, xid, extra=b""):
    p = bytearray(236)
    p[0:3] = b"\x01\x01\x06"; p[4:8] = struct.pack("!I", xid); p[10] = 0x80; p[28:34] = mac
    return bytes(p) + bytes([99, 130, 83, 99, 53, 1, kind]) + extra + b"\xff"

def opts(p):
    o, i = {}, 240
    while i < len(p) and p[i] != 255:
        if p[i] == 0: i += 1; continue
        o[p[i]] = p[i + 2:i + 2 + p[i + 1]]; i += 2 + p[i + 1]
    return o

def ask(kind, xid, extra, want):
    s.sendto(pkt(kind, xid, extra), ("255.255.255.255", 67))
    end = time.time() + 3
    while time.time() < end:
        try: p, _ = s.recvfrom(1500)
        except socket.timeout: break
        if len(p) > 240 and p[0] == 2 and p[4:8] == struct.pack("!I", xid) and opts(p).get(53, b"\0")[0] == want:
            return p
    return None

end = time.time() + secs
while time.time() < end:
    xid = int.from_bytes(os.urandom(4), "big")
    off = ask(1, xid, b"", 2)
    if not off: continue
    ip, srv = off[16:20], opts(off)[54]
    ack = ask(3, xid, bytes([50, 4]) + ip + bytes([54, 4]) + srv, 5)
    if ack:
        bits = bin(struct.unpack("!I", opts(ack).get(1, b"\xff\xff\xff\0"))[0]).count("1")
        a = socket.inet_ntoa(ip)
        subprocess.run(["ip", "addr", "replace", f"{a}/{bits}", "dev", iface], check=True)
        print(a); sys.exit(0)
print("none")
