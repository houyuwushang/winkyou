"""Independent, stdlib-only WYCL byte-vector check; no network or file writes."""
import hashlib
import json
from pathlib import Path
import struct


def checksum(data):
    value = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


vectors = json.loads(Path(__file__).with_name("liveness-wire.json").read_text())
assert len(vectors) == 4
for vector in vectors:
    role, kind = vector["role"], vector["kind"]
    source, destination = bytes((192, 0, 2, role)), bytes((192, 0, 2, 3 - role))
    binding = hashlib.sha256(
        b"winkyou-gate-c-liveness-attempt/1\0synthetic-liveness-attempt"
    ).digest()[:16]
    payload = (b"WYCL" + bytes((1, kind, role, 0)) + binding
               + bytes((1, 2, 3, 4)) + bytes(12)
               + struct.pack("!Q", 0x0102030405060708) + bytes(range(16)))
    udp = struct.pack("!HHHH", 32113, 32113, 72, 0) + payload
    value = checksum(source + destination + bytes((0, 17)) + struct.pack("!H", 72) + udp) or 65535
    udp = udp[:6] + struct.pack("!H", value) + udp[8:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 92, 0, 0, 64, 17, 0) + source + destination
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    assert (ip + udp).hex() == vector["packet_hex"]
print("WYCL independent vectors=4 bytes=92 payload=64 endian=big checksums=verified")
