#!/bin/bash
# NI-SIB Homework 3 - Hardening Script
# Scenario: Debian/Ubuntu production web server running nginx + PostgreSQL

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo ./harden.sh"
    exit 1
fi

# 1. NETWORK - iptables firewall
# clean state
iptables -F    # flush (delete) all existing rules
iptables -X    # delete all user-defined chains
iptables -Z    # zero the packet/byte counters

# default policy: drop all incoming, allow all outgoing
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# allow loopback (required for local services to communicate)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# allow traffic for connections we already established - ordered, let it in
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# allow SSH with rate limiting (max 3 new connections/min, burst 5) - brute force protection
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 5 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j DROP

# allow HTTP and HTTPS for the web server
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# PostgreSQL only accessible from localhost - no external DB access
iptables -A INPUT -p tcp --dport 5432 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 5432 -j DROP

# allow ICMP ping with rate limit (1/s) - prevent ping flood
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# drop malformed/invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# log everything that made it this far and drop everything else
iptables -A INPUT -j LOG --log-prefix "IPTABLES_DROP: " --log-level 4
iptables -A INPUT -j DROP

# block outbound connections to common C2, reverse-shell ports
iptables -A OUTPUT -p tcp --dport 6667 -j DROP   # common C2 channel
iptables -A OUTPUT -p tcp --dport 4444 -j DROP   # Metasploit default reverse shell
iptables -A OUTPUT -p tcp --dport 1337 -j DROP   # classic backdoor port

# persist rules across reboots
iptables-save > /etc/iptables.rules

# 2. KERNEL - sysctl hardening
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'

# disable IPv6 entirerly - not used, reduces attack surface
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# disable IP forwarding - this machine is not a router
net.ipv4.ip_forward = 0

# SYN flood protection - respond to SYN flood with cookies instead of allocating state
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# disable source routing - prevents crafted packets from dictating their own route (spoofing vector)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# reverse path filtering - drop packets whose source address has no route back (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ignore ICMP redirects - prevents MITM via forged redirect messages
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# ignore broadcast ICMP - prevents smurf amplification attacks
net.ipv4.icmp_echo_ignore_broadcasts = 1

# log martian packets - packets with impossible/spoofed source addresses
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# disable core dumps from SUID binaries - prevents info leakage from privileged processes
fs.suid_dumpable = 0

# ASLR level 2 - randomize stack, heap, and mmap base addresses, makes (binary) exploitation harder
kernel.randomize_va_space = 2

# restrict dmesg to root - kernel logs can reveal memory addresses
kernel.dmesg_restrict = 1

# hide kernel pointers from non-root - prevents info leak for exploit development
kernel.kptr_restrict = 2

# prevent symlink/hardlink TOCTOU attacks in world-writable dirs like /tmp
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# system-wide open file limit
fs.file-max = 65535

# TCP keepalive- detect dead connections faster
# dead connection gets cleaned up after 900s
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5

EOF

sysctl -p /etc/sysctl.d/99-hardening.conf > /dev/null 2>&1 || true

# 3. SERVICES - disable what shouldn't be running
# these services have no place on a headless web server
UNNECESSARY_SERVICES=(
    "cups"           # printing
    "cups-browsed"   # printer discovery
    "avahi-daemon"   # mDNS/zeroconf - unnecessary network exposure
    "bluetooth"      # bluetooth
    "ModemManager"   # modem management- not used with server's ethernet
    "whoopsie"       # Ubuntu crash reporting - leaks system info
    "apport"         # crash reporting
    "rpcbind"        # NFS/RPC
    "nfs-server"     # NFS
    "smbd"           # Samba file sharing
    "nmbd"           # Samba name resolution
    "snapd"          # snap daemon - unnecessary overhead and attack surface
    "telnet"         # leggacy plaintext remote access - do not use 
)

for svc in "${UNNECESSARY_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null
        systemctl disable "$svc" 2>/dev/null
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl disable "$svc" 2>/dev/null
        # surpress error so it doesnt crash
    fi
done

# 4. USERS - access control and SSH hardening
# password aging policy
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs   # force rotation every 90 days
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/'  /etc/login.defs   # prevent immediate re-change
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/'  /etc/login.defs   # minimum 12 character passwords
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs   # warn 14 days before expiry

# SSH hardening
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'         /etc/ssh/sshd_config   # no direct root login through ssh
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/'                /etc/ssh/sshd_config   # lock out after 3 wrong attempts
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/'             /etc/ssh/sshd_config   # no X11 forwarding (useless and risky on server)
sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/'   /etc/ssh/sshd_config   # prevent SSH tunneling abuse
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config  # disconnect idle sessions after 10 min
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/'  /etc/ssh/sshd_config

# login warning banner probably should be announced
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
cat > /etc/issue.net << 'EOF'
*************************************************************
WARNING: Unauthorized access to this system is prohibited.
All activity is monitored and logged.
*************************************************************
EOF

# restrictive umask: new files default to 640, dirs to 750
# put to both so cover all types of sessions
echo "umask 027" >> /etc/profile
echo "umask 027" >> /etc/bash.bashrc

# restrict cron to root only
echo "root" > /etc/cron.allow 2>/dev/null || true
touch /etc/cron.deny 2>/dev/null || true

# lock down sensitive authentication files
chmod 600 /etc/shadow  2>/dev/null || true # encrypted passwords
chmod 600 /etc/gshadow 2>/dev/null || true 
chmod 644 /etc/passwd  2>/dev/null || true # user IDs 
chmod 644 /etc/group   2>/dev/null || true
chmod 700 /root        2>/dev/null || true

# 5. SYSTEM RESOURCES - prevent abuse and Denial of Service

cat > /etc/security/limits.d/99-hardening.conf << 'EOF'
# cap process count per user - prevents fork bombs
*    hard    nproc     256
root hard    nproc     512

# limit open file descriptors
*    hard    nofile    4096
root hard    nofile    65535

# cap virtual memory per user (512MB in KB) - prevents memory exhaustion
*    hard    as        524288

# max CPU time per process (60 minutes) - kills runaway processes
*    hard    cpu       60
EOF

mkdir -p /etc/systemd/system/user.slice.d/limits.conf
cat > /etc/systemd/system/user.slice.d/limits.conf  << 'EOF' 
[Slice]
CPUQuota=50%
MemoryMax=2G
TasksMax=512
EOF

# limit nginx via systemd cgroup (applied at service level, not per user)
mkdir -p /etc/systemd/system/nginx.service.d/
cat > /etc/systemd/system/nginx.service.d/limits.conf << 'EOF'
[Service]
CPUQuota=80%
MemoryMax=512M
MemoryHigh=400M
LimitNOFILE=4096
EOF

# limit PostgreSQL via systemd cgroup
mkdir -p /etc/systemd/system/postgresql.service.d/
cat > /etc/systemd/system/postgresql.service.d/limits.conf << 'EOF'
[Service]
CPUQuota=70%
MemoryMax=1G
MemoryHigh=800M
LimitNOFILE=8192
EOF

# reload to load the config files
systemctl daemon-reload 2>/dev/null || true

