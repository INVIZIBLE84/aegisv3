# detection/network_engine.py
"""
Network Monitor Engine - Aegis-LX
====================================
Catches exfiltration and C2 connections regardless of what tool is used.
curl, wget, python requests, nc, custom binary — all caught the same way
because we watch the KERNEL CONNECT SYSCALL, not the process name.

THREE detection strategies:

1. UNEXPECTED PROCESS CONNECTING
   A process that has no business making network calls suddenly
   initiates an outbound connection.
   e.g. postgres, nginx, java connecting to external IPs.

2. KNOWN SAFE PROCESS TO UNEXPECTED PORT/IP
   curl/wget connecting to non-standard ports = likely exfil or C2.
   e.g. curl connecting to port 4444 instead of 80/443.

3. VOLUME SPIKE
   A process suddenly making many connections in a short window.
   e.g. nmap-style scanning or bulk exfil.
"""

import time
from collections import defaultdict

# ── Processes that are ALLOWED to make outbound connections ──────────────────
# Everything not in this list connecting outbound = suspicious
NETWORK_ALLOWED = {
    # System updates and package managers
    "apt", "apt-get", "dpkg", "snap", "snapd", "unattended-upgr",
    # Web/transfer tools (allowed but port-monitored)
    "curl", "wget", "ssh", "scp", "rsync", "git", "ftp",
    # DNS and time
    "systemd-resolve", "chronyd", "ntpd", "avahi-daemon",
    # Remote access
    "sshd",
    # Browsers (desktop)
    "firefox", "chromium", "chrome",
    # Common services that need outbound
    "NetworkManager", "dhclient", "dhcpcd",
    "python3", "python",   # allowed but port-monitored (see below)
    "node", "nodejs",      # allowed but port-monitored
}

# ── Ports that are ALWAYS suspicious for outbound connections ────────────────
# Legitimate services don't connect outbound on these ports
SUSPICIOUS_PORTS = {
    4444,   # Metasploit default
    4445,   # Metasploit alt
    5555,   # Android ADB / common C2
    6666,   # Common backdoor
    7777,   # Common backdoor
    8888,   # Jupyter / common C2
    9001,   # Tor / common C2
    9999,   # Common exfil port
    1234,   # Common test/nc port
    1337,   # "Leet" port — common in CTFs/attacks
    31337,  # "Elite" port — classic backdoor
}

# ── Standard web ports — always allowed ──────────────────────────────────────
SAFE_PORTS = {80, 443, 8080, 8443, 53, 22, 21, 25, 587, 993, 995, 123, 67, 68}

# ── Processes that should NEVER initiate outbound connections ─────────────────
NEVER_CONNECT_OUT = {
    "nginx", "apache2", "httpd", "lighttpd",
    "postgres", "mysqld", "mongod", "redis-server",
    "sshd",   # sshd ACCEPTS connections, never initiates them
    "bash", "sh", "zsh", "dash",   # shells connecting out = reverse shell
}


class NetworkEngine:
    """
    Analyzes outbound connection events from collect_network_events().
    Returns list of network alert dicts.
    """

    def __init__(self):
        # Track connection counts per process for volume detection
        # pid -> list of timestamps
        self.conn_times = defaultdict(list)
        self.VOLUME_WINDOW  = 30    # seconds
        self.VOLUME_THRESH  = 10    # connections in window = suspicious

    def analyze(self, net_events):
        alerts = []
        now = time.time()

        for ev in net_events:
            proc  = ev.get("process_name", "unknown")
            pid   = ev.get("pid")
            dip   = ev.get("dest_ip", "")
            dport = ev.get("dest_port", 0)
            ts    = ev.get("timestamp", "")

            # Track volume
            self.conn_times[pid].append(now)
            # Clean old entries outside window
            self.conn_times[pid] = [
                t for t in self.conn_times[pid]
                if now - t <= self.VOLUME_WINDOW
            ]
            conn_count = len(self.conn_times[pid])

            # ── Check 1: process that should NEVER connect out ────────────
            if proc in NEVER_CONNECT_OUT:
                alerts.append({
                    "source":  "NETWORK",
                    "process": proc,
                    "pid":     pid,
                    "dest":    dip + ":" + str(dport),
                    "phase":   "EXECUTION",
                    "tier":    4,
                    "mitre":   "T1095 (Non-App Layer Protocol) / T1048 (Exfil)",
                    "detail":  proc + " initiated outbound connection to " +
                               dip + ":" + str(dport) + " -- reverse shell or exfil",
                    "timestamp": ts,
                })
                continue

            # ── Check 2: connection to known suspicious port ───────────────
            if dport in SUSPICIOUS_PORTS:
                alerts.append({
                    "source":  "NETWORK",
                    "process": proc,
                    "pid":     pid,
                    "dest":    dip + ":" + str(dport),
                    "phase":   "EXFILTRATION",
                    "tier":    4,
                    "mitre":   "T1048 (Exfiltration Over Alternative Protocol)",
                    "detail":  proc + " connected to suspicious port " +
                               str(dport) + " on " + dip,
                    "timestamp": ts,
                })
                continue

            # ── Check 3: unexpected process connecting out ────────────────
            if proc not in NETWORK_ALLOWED and dport not in SAFE_PORTS:
                alerts.append({
                    "source":  "NETWORK",
                    "process": proc,
                    "pid":     pid,
                    "dest":    dip + ":" + str(dport),
                    "phase":   "EXFILTRATION",
                    "tier":    3,
                    "mitre":   "T1041 (Exfiltration Over C2 Channel)",
                    "detail":  proc + " (unexpected) connected to " +
                               dip + ":" + str(dport),
                    "timestamp": ts,
                })
                continue

            # ── Check 4: connection volume spike ──────────────────────────
            if conn_count >= self.VOLUME_THRESH:
                alerts.append({
                    "source":  "NETWORK",
                    "process": proc,
                    "pid":     pid,
                    "dest":    dip + ":" + str(dport),
                    "phase":   "EXFILTRATION",
                    "tier":    3,
                    "mitre":   "T1046 (Network Service Scanning) / T1048 (Exfil)",
                    "detail":  proc + " made " + str(conn_count) +
                               " connections in " + str(self.VOLUME_WINDOW) +
                               "s -- possible scan or bulk exfil",
                    "timestamp": ts,
                })

        return alerts
