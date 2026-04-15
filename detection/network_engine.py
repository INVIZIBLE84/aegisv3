# detection/network_engine.py
"""
Network Monitor Engine - Aegis-LX
====================================
Detects suspicious outbound connections via /proc/net/tcp polling.
Resolves socket inode -> PID using fast /proc/pid/fd scan.
No eBPF connect hook needed.
"""

import os
import socket
import struct
import time
from collections import defaultdict

SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 7777, 8888,
    9001, 9999, 1234, 1337, 31337,
}

SAFE_PORTS = {
    80, 443, 8080, 8443, 53, 22, 21,
    25, 587, 993, 995, 123, 67, 68, 3128,
}

NEVER_CONNECT_OUT = {
    "nginx", "apache2", "httpd", "lighttpd",
    "postgres", "mysqld", "mongod", "redis-server",
    "bash", "sh", "zsh", "dash",
}

NETWORK_ALLOWED = {
    "apt", "apt-get", "dpkg", "snap", "snapd", "unattended-upgr",
    "curl", "wget", "ssh", "scp", "rsync", "git", "ftp",
    "systemd-resolve", "chronyd", "ntpd", "avahi-daemon",
    "sshd", "firefox", "chromium", "chrome",
    "NetworkManager", "dhclient", "dhcpcd",
    "python3", "python", "node", "nodejs",
}


def _build_inode_pid_map():
    """Scan /proc/*/fd once and return {inode_str -> pid_str} map."""
    imap = {}
    try:
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            fd_dir = "/proc/%s/fd" % pid_str
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink("%s/%s" % (fd_dir, fd))
                        if link.startswith("socket:["):
                            imap[link[8:-1]] = pid_str
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    return imap


def _get_comm(pid_str):
    try:
        with open("/proc/%s/comm" % pid_str) as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def _read_tcp_conns():
    """Read /proc/net/tcp and return active outbound connections."""
    conns = []
    try:
        with open("/proc/net/tcp") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            state = parts[3]
            # 01=ESTABLISHED, 02=SYN_SENT
            if state not in ("01", "02"):
                continue
            remote = parts[2]
            inode  = parts[9]
            rip_hex, rport_hex = remote.split(":")
            try:
                rip   = socket.inet_ntoa(struct.pack("<I", int(rip_hex, 16)))
                rport = int(rport_hex, 16)
            except Exception:
                continue
            # Skip loopback
            if rip.startswith("127.") or rip == "0.0.0.0" or rport == 0:
                continue
            conns.append({"inode": inode, "remote_ip": rip, "remote_port": rport})
    except Exception:
        pass
    return conns


class NetworkEngine:
    def __init__(self):
        self.seen       = set()          # inodes already reported
        self.conn_times = defaultdict(list)
        self.VOLUME_WIN = 60
        self.VOLUME_TH  = 8

    def analyze(self, _unused=None):
        alerts = []
        now    = time.time()

        conns     = _read_tcp_conns()
        if not conns:
            return []

        # Build inode->pid map once per cycle
        inode_map = _build_inode_pid_map()

        for conn in conns:
            inode = conn["inode"]
            rip   = conn["remote_ip"]
            rport = conn["remote_port"]

            # Already reported this connection
            if inode in self.seen:
                continue
            self.seen.add(inode)

            # Keep seen set bounded
            if len(self.seen) > 2000:
                self.seen = set(list(self.seen)[-1000:])

            # Resolve process
            pid_str = inode_map.get(inode)
            if not pid_str:
                continue
            proc = _get_comm(pid_str)
            if not proc or proc == "unknown":
                continue

            dest = rip + ":" + str(rport)

            # Volume tracking
            self.conn_times[proc].append(now)
            self.conn_times[proc] = [
                t for t in self.conn_times[proc]
                if now - t <= self.VOLUME_WIN
            ]
            count = len(self.conn_times[proc])

            # Check 1: process that should NEVER connect outbound
            if proc in NEVER_CONNECT_OUT:
                alerts.append(self._alert(proc, pid_str, dest, rport,
                    "EXECUTION", 4,
                    proc + " made outbound connection to " + dest +
                    " -- reverse shell or exfil"))
                continue

            # Check 2: known attack port
            if rport in SUSPICIOUS_PORTS:
                alerts.append(self._alert(proc, pid_str, dest, rport,
                    "EXFILTRATION", 4,
                    proc + " connected to attack port " + str(rport) +
                    " on " + rip))
                continue

            # Check 3: unexpected process on non-standard port
            if proc not in NETWORK_ALLOWED and rport not in SAFE_PORTS:
                alerts.append(self._alert(proc, pid_str, dest, rport,
                    "EXFILTRATION", 3,
                    proc + " (unexpected process) connected to " + dest))
                continue

            # Check 4: volume spike
            if count >= self.VOLUME_TH:
                alerts.append(self._alert(proc, pid_str, dest, rport,
                    "EXFILTRATION", 3,
                    proc + " made " + str(count) +
                    " connections in " + str(self.VOLUME_WIN) + "s"))

        return alerts

    def _alert(self, proc, pid, dest, port, phase, tier, detail):
        return {
            "source":  "NETWORK",
            "process": proc,
            "pid":     pid,
            "dest":    dest,
            "phase":   phase,
            "tier":    tier,
            "mitre":   "T1048 (Exfiltration) / T1095 (Non-App Layer Protocol)",
            "detail":  detail,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
