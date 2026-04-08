#!/usr/bin/env python3
"""
NI-SIB Homework 3 - SSH Honeypot
A fake SSH server that logs attacker activity and presents a convincing shell.
Run inside Docker for sandboxing.
"""

import socket
import threading
import paramiko
import json
import datetime
import os
import sys
import hashlib

# Configuration
HOST = "0.0.0.0" # host all
PORT = 22
LOG_FILE = "/var/log/honeypot/honeypot.json"
HOST_KEY_FILE = "/etc/honeypot/ssh_host_rsa_key"
MAX_AUTH_ATTEMPTS = 3  # let attacker in after this many tries
FAKE_HOSTNAME = "prod-db-01"
FAKE_USER = "admin"

# Logging
log_lock = threading.Lock()

def log_event(event_type, client_ip, **kwargs):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event": event_type,
        "source_ip": client_ip,
    }
    entry.update(kwargs)

    with log_lock:
        print(f"[{entry['timestamp']}] {event_type} from {client_ip}: {kwargs}")
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

# Fake filesystem
FAKE_FS = {
    "/": ["bin", "etc", "home", "root", "tmp", "var", "usr", "opt"],
    "/etc": ["passwd", "shadow", "hostname", "ssh", "crontab", "resolv.conf"],
    "/etc/ssh": ["sshd_config", "ssh_host_rsa_key", "ssh_host_rsa_key.pub"],
    "/home": ["admin", "deploy", "backup"],
    "/home/admin": [".bash_history", ".ssh", "notes.txt", "passwords.txt", "backup.sh"],
    "/home/admin/.ssh": ["id_rsa", "id_rsa.pub", "authorized_keys", "known_hosts"],
    "/root": [".bash_history", ".ssh", "maintenance.sh"],
    "/tmp": ["sess_a8f3e2", ".hidden_cache"],
    "/var": ["log", "www", "backups"],
    "/var/log": ["auth.log", "syslog", "access.log"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "config.php", ".env"],
    "/var/backups": ["db_dump_2025-03-15.sql.gz", "db_dump_2025-04-01.sql.gz"],
    "/opt": ["app", "monitoring"],
}

FAKE_FILES = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "sshd:x:74:74:sshd:/var/run/sshd:/usr/sbin/nologin\n"
        "admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
        "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
        "backup:x:1002:1002:Backup Service:/home/backup:/usr/sbin/nologin\n"
        "postgres:x:999:999:PostgreSQL:/var/lib/postgresql:/bin/bash\n"
        "mysql:x:998:998:MySQL:/var/lib/mysql:/bin/false\n"
    ),
    "/etc/shadow": (
        "root:$6$rounds=5000$randomsalt$KjZyR3n8v2QlMcP9xW4tB7dF1gH5kL0mN8pR2sT4vX6zA:19800:0:99999:7:::\n"
        "admin:$6$rounds=5000$adminsalt$Yt7Kp2Wn4Qr8Lm1Xv6Hb3Df9Gj5Ck0Es7Au2Iw4Oz8Nx:19800:0:99999:7:::\n"
        "deploy:$6$rounds=5000$depsalt01$Mn3Kq8Wr2Lp5Hx7Bt1Df4Gj6Ck9Es0Au3Iv7Ow2Nz5Ry:19800:0:99999:7:::\n"
        "postgres:$6$rounds=5000$pgsalt999$Jk2Mp7Qn1Lo4Gw6As9Cf3Dh5Ei8Bv0Ft2Hu4Ix6Ny3Rz:19800:0:99999:7:::\n"
    ),
    "/etc/hostname": f"{FAKE_HOSTNAME}\n",
    "/etc/resolv.conf": "nameserver 10.0.1.1\nnameserver 8.8.8.8\nsearch internal.corp\n",
    "/etc/crontab": (
        "# /etc/crontab\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "0 2 * * * root /opt/monitoring/backup.sh\n"
        "*/5 * * * * root /opt/monitoring/health_check.sh\n"
        "0 3 * * 0 admin /home/admin/backup.sh\n"
    ),
    "/home/admin/passwords.txt": (
        "# Internal service credentials - DO NOT SHARE\n"
        "# Last updated: 2025-03-20\n"
        "\n"
        "PostgreSQL (prod):\n"
        "  host: db-master.internal.corp:5432\n"
        "  user: app_readwrite\n"
        "  pass: Pr0d_DB!2025_s3cure\n"
        "  database: customer_data\n"
        "\n"
        "Redis (cache):\n"
        "  host: cache-01.internal.corp:6379\n"
        "  pass: R3d1s_C@che_Key!\n"
        "\n"
        "Admin panel:\n"
        "  url: https://admin.internal.corp/login\n"
        "  user: superadmin\n"
        "  pass: Ch@ngeM3_N0w!2025\n"
        "\n"
        "AWS S3 (backups):\n"
        "  access_key: AKIAIOSFODNN7EXAMPLE\n"
        "  secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "  bucket: corp-prod-backups\n"
    ),
    "/home/admin/notes.txt": (
        "TODO:\n"
        "- Migrate database to new cluster by end of April\n"
        "- Update SSL certificates (expiring May 15)\n"
        "- Fix the memory leak in the payment service\n"
        "- Ask John about the VPN credentials for the staging env\n"
        "- Rotate AWS keys (been 6 months...)\n"
    ),
    "/home/admin/backup.sh": (
        "#!/bin/bash\n"
        "# Weekly database backup script\n"
        "TIMESTAMP=$(date +%Y-%m-%d)\n"
        "pg_dump -h db-master.internal.corp -U app_readwrite customer_data | "
        "gzip > /var/backups/db_dump_${TIMESTAMP}.sql.gz\n"
        "echo \"Backup completed: ${TIMESTAMP}\" >> /var/log/backup.log\n"
    ),
    "/home/admin/.bash_history": (
        "sudo systemctl restart postgresql\n"
        "cat /etc/shadow\n"
        "ssh deploy@staging-01.internal.corp\n"
        "psql -h db-master.internal.corp -U app_readwrite customer_data\n"
        "SELECT count(*) FROM users;\n"
        "scp /var/backups/db_dump_2025-03-15.sql.gz admin@backup-srv:/mnt/archive/\n"
        "curl -s https://admin.internal.corp/api/health\n"
        "docker ps\n"
        "cat passwords.txt\n"
        "sudo iptables -L\n"
        "netstat -tlnp\n"
        "vim /opt/app/config/database.yml\n"
        "git log --oneline -10\n"
        "ping db-replica-02.internal.corp\n"
    ),
    "/home/admin/.ssh/id_rsa": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA3F7xKz2N8v5Qp1R9m4Lh0G6jY8dW2cXi7tB5nA9kE4fJ3gH\n"
        "7iL2mO0pR4sT6uW8xZ1aC3eB5gI7kM9oQ1sU3wY5bD7fH9jL1nP3rT5vX7zA2cE\n"
        "4gI6kM8oQ0sU2wY4bD6fH8jL0nP2rT4vX6zA1cE3gI5kM7oQ9sU1wY3bD5fH7jL\n"
        "9nP1rT3vX5yA0cE2gI4kM6oQ8sU0wY2bD4fH6jL8nP0rT2vX4yZ9cE1gI3kM5oQ\n"
        "FAKE_KEY_DO_NOT_USE_FAKE_KEY_DO_NOT_USE_FAKE_KEY_DO_NOT_USE_FAKEKE\n"
        "7sU9wY1bD3fH5jL7nO9rT1vX3yZ8cE0gI2kM4oQ6sU8wY0bD2fH4jL6nO8rT0vX\n"
        "2yZ7cD9gI1kM3oQ5sU7wX9bD1fH3jL5nO7rS9vX1yZ6cD8gI0kM2oQ4sU6wX8bD\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "/home/admin/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...FAKE...KEY admin@prod-db-01\n"
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...FAKE...KEY deploy@ci-server\n"
    ),
    "/var/www/html/.env": (
        "APP_NAME=CorpPortal\n"
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        "APP_URL=https://portal.internal.corp\n"
        "DB_CONNECTION=pgsql\n"
        "DB_HOST=db-master.internal.corp\n"
        "DB_PORT=5432\n"
        "DB_DATABASE=customer_data\n"
        "DB_USERNAME=app_readwrite\n"
        "DB_PASSWORD=Pr0d_DB!2025_s3cure\n"
        "REDIS_HOST=cache-01.internal.corp\n"
        "REDIS_PASSWORD=R3d1s_C@che_Key!\n"
        "MAIL_MAILER=smtp\n"
        "MAIL_HOST=mail.internal.corp\n"
        "MAIL_PORT=587\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ),
    "/root/.bash_history": (
        "apt update && apt upgrade -y\n"
        "useradd -m -s /bin/bash deploy\n"
        "passwd deploy\n"
        "visudo\n"
        "systemctl enable sshd\n"
        "ufw allow 22/tcp\n"
        "ufw allow 443/tcp\n"
        "ufw enable\n"
    ),
}

class FakeShell:
    def __init__(self, client_ip, username):
        self.client_ip = client_ip
        self.username = username
        self.cwd = f"/home/{username}" if username != "root" else "/root"
        self.home = self.cwd
        self.hostname = FAKE_HOSTNAME
        self.env = {
            "USER": username,
            "HOME": self.home,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
        }

    def get_prompt(self):
        display_cwd = self.cwd.replace(self.home, "~") if self.cwd.startswith(self.home) else self.cwd
        symbol = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{display_cwd}{symbol} "

    def resolve_path(self, path):
        if not path or path == "~":
            return self.home
        if path.startswith("~/"):
            path = self.home + path[1:]
        if not path.startswith("/"):
            path = self.cwd + "/" + path

        # normalize path (resolve . and ..)
        parts = []
        for p in path.split("/"):
            if p == "" or p == ".":
                continue
            elif p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        return "/" + "/".join(parts) if parts else "/"

    def execute(self, command):
        command = command.strip()
        if not command:
            return ""

        log_event("command", self.client_ip, username=self.username, command=command)

        parts = command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        handlers = {
            "ls": self.cmd_ls,
            "cat": self.cmd_cat,
            "cd": self.cmd_cd,
            "pwd": self.cmd_pwd,
            "whoami": self.cmd_whoami,
            "id": self.cmd_id,
            "uname": self.cmd_uname,
            "hostname": self.cmd_hostname,
            "ifconfig": self.cmd_ifconfig,
            "ip": self.cmd_ip,
            "ps": self.cmd_ps,
            "netstat": self.cmd_netstat,
            "ss": self.cmd_netstat,
            "w": self.cmd_w,
            "uptime": self.cmd_uptime,
            "df": self.cmd_df,
            "free": self.cmd_free,
            "echo": self.cmd_echo,
            "env": self.cmd_env,
            "export": self.cmd_export,
            "history": self.cmd_history,
            "head": self.cmd_head,
            "tail": self.cmd_tail,
            "grep": self.cmd_grep,
            "find": self.cmd_find,
            "wget": self.cmd_wget,
            "curl": self.cmd_curl,
            "sudo": self.cmd_sudo,
            "su": self.cmd_su,
            "exit": self.cmd_exit,
            "logout": self.cmd_exit,
            "clear": self.cmd_clear,
            "touch": self.cmd_touch,
            "mkdir": self.cmd_mkdir,
            "rm": self.cmd_rm,
            "cp": self.cmd_cp,
            "mv": self.cmd_mv,
            "chmod": self.cmd_chmod,
            "chown": self.cmd_chown,
            "tar": self.cmd_tar,
            "unzip": self.cmd_unzip,
            "apt": self.cmd_apt,
            "yum": self.cmd_apt,
            "systemctl": self.cmd_systemctl,
            "service": self.cmd_systemctl,
            "docker": self.cmd_docker,
            "ssh": self.cmd_ssh,
            "scp": self.cmd_scp,
            "ping": self.cmd_ping,
            "nmap": self.cmd_nmap,
        }

        handler = handlers.get(cmd)
        if handler:
            return handler(args)
        else:
            return f"-bash: {cmd}: command not found\n"

    def cmd_ls(self, args):
        target = self.cwd
        show_all = False
        show_long = False
        for a in args:
            if a.startswith("-"):
                if "a" in a: show_all = True
                if "l" in a: show_long = True
            else:
                target = self.resolve_path(a)

        entries = FAKE_FS.get(target)
        if entries is None:
            return f"ls: cannot access '{args[0] if args else target}': No such file or directory\n"

        if show_all:
            entries = [".", ".."] + entries

        if show_long:
            lines = [f"total {len(entries) * 4}"]
            for e in entries:
                full = target.rstrip("/") + "/" + e if e not in [".", ".."] else target
                if full in FAKE_FS or e in [".", ".."]:
                    lines.append(f"drwxr-xr-x  2 {self.username} {self.username}  4096 Mar 20 14:30 {e}")
                else:
                    size = len(FAKE_FILES.get(full, "")) or 1024
                    lines.append(f"-rw-r--r--  1 {self.username} {self.username}  {size:>4} Mar 20 14:30 {e}")
            return "\n".join(lines) + "\n"
        else:
            return "  ".join(entries) + "\n"

    def cmd_cat(self, args):
        if not args:
            return ""
        path = self.resolve_path(args[0])
        content = FAKE_FILES.get(path)
        if content:
            return content
        elif path in FAKE_FS:
            return f"cat: {args[0]}: Is a directory\n"
        else:
            return f"cat: {args[0]}: No such file or directory\n"

    def cmd_cd(self, args):
        target = self.resolve_path(args[0] if args else "~")
        if target in FAKE_FS:
            self.cwd = target
            return ""
        else:
            return f"-bash: cd: {args[0]}: No such file or directory\n"

    def cmd_pwd(self, args):
        return self.cwd + "\n"

    def cmd_whoami(self, args):
        return self.username + "\n"

    def cmd_id(self, args):
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo),33(www-data)\n"

    def cmd_uname(self, args):
        if args and "-a" in " ".join(args):
            return f"Linux {self.hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
        return "Linux\n"

    def cmd_hostname(self, args):
        return self.hostname + "\n"

    def cmd_ifconfig(self, args):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.1.47  netmask 255.255.255.0  broadcast 10.0.1.255\n"
            "        inet6 fe80::a00:27ff:fe4e:1234  prefixlen 64  scopeid 0x20<link>\n"
            "        ether 08:00:27:4e:12:34  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 284756  bytes 189234567 (189.2 MB)\n"
            "        TX packets 134892  bytes 45678901 (45.6 MB)\n"
            "\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
            "        loop  txqueuelen 1000  (Local Loopback)\n"
        )

    def cmd_ip(self, args):
        return self.cmd_ifconfig(args)

    def cmd_ps(self, args):
        return (
            "  PID TTY          TIME CMD\n"
            "    1 ?        00:00:03 systemd\n"
            "  456 ?        00:00:01 sshd\n"
            "  789 ?        00:00:12 postgres\n"
            "  801 ?        00:00:05 redis-server\n"
            "  923 ?        00:00:08 nginx\n"
            " 1045 ?        00:00:22 node /opt/app/server.js\n"
            " 1234 ?        00:00:00 cron\n"
            f" 2048 pts/0    00:00:00 bash\n"
            f" 2099 pts/0    00:00:00 ps\n"
        )

    def cmd_netstat(self, args):
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN\n"
        )

    def cmd_w(self, args):
        now = datetime.datetime.utcnow().strftime("%H:%M:%S")
        return (
            f" {now} up 47 days,  3:22,  1 user,  load average: 0.12, 0.08, 0.05\n"
            f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{self.username:<8} pts/0    attacker         {now}   0.00s  0.01s  0.00s w\n"
        )

    def cmd_uptime(self, args):
        now = datetime.datetime.utcnow().strftime("%H:%M:%S")
        return f" {now} up 47 days,  3:22,  1 user,  load average: 0.12, 0.08, 0.05\n"

    def cmd_df(self, args):
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   23G   25G  48% /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
            "/dev/sda2       200G  156G   35G  82% /var\n"
        )

    def cmd_free(self, args):
        return (
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:        4038912     1523456      987632       45672     1527824     2234576\n"
            "Swap:       2097148       12340     2084808\n"
        )

    def cmd_echo(self, args):
        return " ".join(args) + "\n"

    def cmd_env(self, args):
        return "".join(f"{k}={v}\n" for k, v in self.env.items())

    def cmd_export(self, args):
        for a in args:
            if "=" in a:
                k, v = a.split("=", 1)
                self.env[k] = v
        return ""

    def cmd_history(self, args):
        hist = FAKE_FILES.get(f"{self.home}/.bash_history", "")
        lines = hist.strip().split("\n")
        return "".join(f"  {i+1}  {line}\n" for i, line in enumerate(lines))

    def cmd_head(self, args):
        if not args: return ""
        content = self.cmd_cat(args)
        lines = content.split("\n")[:10]
        return "\n".join(lines) + "\n"

    def cmd_tail(self, args):
        if not args: return ""
        content = self.cmd_cat([a for a in args if not a.startswith("-")])
        lines = content.strip().split("\n")[-10:]
        return "\n".join(lines) + "\n"

    def cmd_grep(self, args):
        if len(args) < 2: return "Usage: grep PATTERN FILE\n"
        pattern = args[0]
        path = self.resolve_path(args[1])
        content = FAKE_FILES.get(path, "")
        matches = [line for line in content.split("\n") if pattern.lower() in line.lower()]
        return "\n".join(matches) + "\n" if matches else ""

    def cmd_find(self, args):
        results = []
        search_dir = args[0] if args else "."
        resolved = self.resolve_path(search_dir)
        for path in FAKE_FS:
            if path.startswith(resolved):
                for entry in FAKE_FS[path]:
                    results.append(path.rstrip("/") + "/" + entry)
        return "\n".join(results[:20]) + "\n"

    def cmd_wget(self, args):
        log_event("download_attempt", self.client_ip, command=f"wget {' '.join(args)}")
        return f"Connecting to {args[0] if args else 'unknown'}... failed: Connection timed out.\n"

    def cmd_curl(self, args):
        log_event("download_attempt", self.client_ip, command=f"curl {' '.join(args)}")
        return f"curl: (28) Connection timed out after 30000 milliseconds\n"

    def cmd_sudo(self, args):
        if not args:
            return "usage: sudo [-h] [-u user] command\n"
        log_event("sudo_attempt", self.client_ip, username=self.username, command=f"sudo {' '.join(args)}")
        self.username = "root"
        self.env["USER"] = "root"
        return self.execute(" ".join(args))

    def cmd_su(self, args):
        log_event("su_attempt", self.client_ip, username=self.username)
        self.username = "root"
        self.cwd = "/root"
        self.home = "/root"
        self.env["USER"] = "root"
        self.env["HOME"] = "/root"
        return ""

    def cmd_exit(self, args):
        return "__EXIT__"

    def cmd_clear(self, args):
        return "\033[2J\033[H"

    def cmd_touch(self, args):
        return ""

    def cmd_mkdir(self, args):
        return ""

    def cmd_rm(self, args):
        log_event("destructive_command", self.client_ip, command=f"rm {' '.join(args)}")
        return ""

    def cmd_cp(self, args):
        return ""

    def cmd_mv(self, args):
        return ""

    def cmd_chmod(self, args):
        return ""

    def cmd_chown(self, args):
        return ""

    def cmd_tar(self, args):
        return ""

    def cmd_unzip(self, args):
        return ""

    def cmd_apt(self, args):
        return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"

    def cmd_systemctl(self, args):
        if not args: return ""
        return f"  {args[-1]}.service - Service\n   Loaded: loaded\n   Active: active (running)\n"

    def cmd_docker(self, args):
        return (
            "CONTAINER ID   IMAGE          COMMAND       STATUS          NAMES\n"
            "a1b2c3d4e5f6   node:18        \"npm start\"   Up 12 days      app-backend\n"
            "f6e5d4c3b2a1   nginx:latest   \"nginx -g\"    Up 12 days      reverse-proxy\n"
            "1a2b3c4d5e6f   redis:7        \"redis-srv\"   Up 12 days      cache\n"
        )

    def cmd_ssh(self, args):
        log_event("lateral_movement", self.client_ip, command=f"ssh {' '.join(args)}")
        return f"ssh: connect to host {args[0] if args else 'unknown'} port 22: Connection timed out\n"

    def cmd_scp(self, args):
        log_event("exfiltration_attempt", self.client_ip, command=f"scp {' '.join(args)}")
        return f"ssh: connect to host remote port 22: Connection timed out\n"

    def cmd_ping(self, args):
        target = args[0] if args else "unknown"
        return (
            f"PING {target} ({target}) 56(84) bytes of data.\n"
            f"64 bytes from {target}: icmp_seq=1 ttl=64 time=0.42 ms\n"
            f"64 bytes from {target}: icmp_seq=2 ttl=64 time=0.38 ms\n"
            f"--- {target} ping statistics ---\n"
            f"2 packets transmitted, 2 received, 0% packet loss\n"
        )

    def cmd_nmap(self, args):
        log_event("recon_attempt", self.client_ip, command=f"nmap {' '.join(args)}")
        return "bash: nmap: command not found\n"


# SSH server implementation
class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.auth_attempts = 0
        self.event = threading.Event()
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.auth_attempts += 1
        log_event("login_attempt", self.client_ip,
                  username=username, password=password,
                  attempt=self.auth_attempts)

        # let them in after MAX_AUTH_ATTEMPTS tries
        if self.auth_attempts >= MAX_AUTH_ATTEMPTS:
            self.username = username
            log_event("login_success", self.client_ip,
                      username=username, attempt=self.auth_attempts)
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


def handle_client(client_socket, client_addr):
    client_ip = f"{client_addr[0]}:{client_addr[1]}"
    log_event("connection", client_ip)

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

        host_key = paramiko.RSAKey.from_private_key_file(HOST_KEY_FILE)
        transport.add_server_key(host_key)

        server = HoneypotSSHServer(client_ip)
        transport.start_server(server=server)

        channel = transport.accept(60)
        if channel is None:
            log_event("channel_failed", client_ip)
            return

        server.event.wait(30)
        if not server.event.is_set():
            log_event("shell_timeout", client_ip)
            return

        username = server.username or FAKE_USER
        shell = FakeShell(client_ip, username)

        # send fake MOTD
        motd = (
            f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n"
            f"\n"
            f" * Documentation:  https://help.ubuntu.com\n"
            f" * Management:     https://landscape.canonical.com\n"
            f" * Support:        https://ubuntu.com/advantage\n"
            f"\n"
            f"  System information as of {datetime.datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')}\n"
            f"\n"
            f"  System load:  0.12               Processes:           187\n"
            f"  Usage of /:   47.2% of 49.12GB   Users logged in:     1\n"
            f"  Memory usage: 38%                 IPv4 address for eth0: 10.0.1.47\n"
            f"  Swap usage:   0%\n"
            f"\n"
            f"Last login: {(datetime.datetime.utcnow() - datetime.timedelta(hours=3)).strftime('%a %b %d %H:%M:%S %Y')} from 10.0.1.1\n"
        )
        # channel.sendall(motd.encode())
        channel.sendall(motd.replace("\n", "\r\n").encode())
        channel.sendall(shell.get_prompt().encode())

        # command loop
        buffer = ""
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                for byte in data:
                    char = chr(byte)
                    if char == "\r" or char == "\n":
                        channel.sendall(b"\r\n")
                        result = shell.execute(buffer)
                        if result == "__EXIT__":
                            channel.sendall(b"logout\r\n")
                            log_event("logout", client_ip)
                            return
                        if result:
                            channel.sendall(result.replace("\n", "\r\n").encode())
                        channel.sendall(shell.get_prompt().encode())
                        buffer = ""
                    elif char == "\x7f" or char == "\x08":  # backspace
                        if buffer:
                            buffer = buffer[:-1]
                            channel.sendall(b"\x08 \x08")
                    elif char == "\x03":  # Ctrl+C
                        channel.sendall(b"^C\r\n")
                        channel.sendall(shell.get_prompt().encode())
                        buffer = ""
                    elif char == "\x04":  # Ctrl+D
                        log_event("logout", client_ip)
                        return
                    else:
                        buffer += char
                        channel.sendall(char.encode())

            except Exception:
                break

    except Exception as e:
        log_event("error", client_ip, error=str(e))
    finally:
        log_event("disconnect", client_ip)
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass


# Main
def main():
    # generate host key if it doesn't exist
    os.makedirs(os.path.dirname(HOST_KEY_FILE), exist_ok=True)
    if not os.path.exists(HOST_KEY_FILE):
        print("[*] Generating SSH host key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_FILE)

    print(f"[*] SSH Honeypot starting on {HOST}:{PORT}")
    print(f"[*] Logs: {LOG_FILE}")
    print(f"[*] Fake hostname: {FAKE_HOSTNAME}")
    print(f"[*] Auth attempts before access: {MAX_AUTH_ATTEMPTS}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(20)

    print(f"[*] Listening for connections...")

    while True:
        try:
            # try spawning new thread for new connections - multiple attackers at once
            client_socket, client_addr = server_socket.accept()
            print(f"[+] Connection from {client_addr[0]}:{client_addr[1]}")
            t = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot...")
            break
        except Exception as e:
            print(f"[-] Error: {e}")

    server_socket.close()

if __name__ == "__main__":
    main()