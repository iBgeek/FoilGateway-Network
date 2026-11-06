#!/usr/bin/env python3
# Asks for foilgateway.local the way a one-shot resolver does and prints
# the address, or "none". Usage: mdnsq.py IFACE
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, sys.argv[1].encode())
s.settimeout(2)
q = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x0bfoilgateway\x05local\x00" + b"\x00\x01\x00\x01"
s.sendto(q, ("224.0.0.251", 5353))
try:
    a, _ = s.recvfrom(1500)
    print(socket.inet_ntoa(a[-4:]) if a[:2] == b"\x12\x34" else "none")
except socket.timeout:
    print("none")
