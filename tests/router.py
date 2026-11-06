#!/usr/bin/env python3
# Stand-in home router for the bridge tests: DHCP (one address per MAC,
# DNS option pointing at itself) and a DNS server that answers A queries
# from a small table. Usage: router.py IFACE ROUTER_IP
import socket, struct, sys, threading
iface, router = sys.argv[1:3]
base = router.rsplit(".", 1)[0]
names = {"one.test": "1.1.1.1", "nine.test": "9.9.9.9", "eight.test": "8.8.8.8", "router.test": router}
pool = {}

def dhcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
    s.bind(("0.0.0.0", 67))
    while True:
        p, _ = s.recvfrom(1500)
        if len(p) < 240 or p[0] != 1:
            continue
        opts, i, kind, cid = p[240:], 0, 0, None
        while i < len(opts) and opts[i] != 255:
            if opts[i] == 0:
                i += 1; continue
            if opts[i] == 53:
                kind = opts[i + 2]
            if opts[i] == 61:
                cid = opts[i + 2:i + 2 + opts[i + 1]].hex()
            i += 2 + opts[i + 1]
        reply = {1: 2, 3: 5}.get(kind)
        if not reply:
            continue
        mac = p[28:34].hex(":")
        addr = pool.setdefault(cid or mac, f"{base}.{100 + len(pool)}")
        out = bytearray(p[:236])
        out[0] = 2
        out[16:20] = socket.inet_aton(addr)
        out[20:24] = socket.inet_aton(router)
        out += bytes([99, 130, 83, 99, 53, 1, reply, 54, 4]) + socket.inet_aton(router)
        out += bytes([1, 4, 255, 255, 255, 0, 3, 4]) + socket.inet_aton(router)
        out += bytes([6, 4]) + socket.inet_aton(router)
        out += bytes([51, 4]) + struct.pack("!I", 3600) + bytes([255])
        s.sendto(bytes(out), ("255.255.255.255", 68))
        print("dhcp", {2: "offer", 5: "ack"}[reply], mac, cid, addr, flush=True)

def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((router, 53))
    while True:
        q, peer = s.recvfrom(512)
        i, labels = 12, []
        while i < len(q) and q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode()); i += 1 + q[i]
        qend = i + 5
        qname = ".".join(labels).lower()
        qtype = struct.unpack("!H", q[qend - 4:qend - 2])[0] if qend <= len(q) else 1
        # Reverse names for leases on 10.10.10.0/24, like dnsmasq: lanpcN.lan.
        if qtype == 12 and qname.endswith(".10.10.10.in-addr.arpa") and qname.split(".")[0] != "1":
            host = b"".join(bytes([len(x)]) + x.encode() for x in ("lanpc" + qname.split(".")[0], "lan")) + b"\0"
            out = q[:2] + struct.pack("!HHHHH", 0x8580, 1, 1, 0, 0) + q[12:qend] + b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 0, len(host)) + host
            s.sendto(out, peer)
            continue
        ans = names.get(qname)
        head = q[:2] + struct.pack("!HHHHH", 0x8180 if ans else 0x8183, 1, 1 if ans else 0, 0, 0)
        out = head + q[12:qend]
        if ans:
            out += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ans)
        s.sendto(out, peer)

threading.Thread(target=dns, daemon=True).start()
dhcp()
