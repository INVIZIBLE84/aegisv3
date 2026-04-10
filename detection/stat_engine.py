# detection/stat_engine.py
"""
Statistical Anomaly Engine — Aegis-LX
=======================================
Detects BEHAVIOURAL anomalies using Z-score statistics.
No training file needed. Warms up in ~2 minutes by watching normal activity.

4 Detection Layers:
  FREQUENCY    — a specific process running way more than usual
  DIVERSITY    — too many unique processes appearing at once
  VELOCITY     — total execution rate spiking
  NEW_PROCESS  — a process appearing that has never been seen before
"""

import math
from collections import defaultdict, deque

HISTORY_WINDOW       = 180    # 30 min of rolling history (180 × 10s cycles)
WARMUP_CYCLES        = 12     # ~2 minutes before alerts start
Z_THRESHOLD          = 2.5    # For diversity, velocity, new_process layers
Z_THRESHOLD_FREQ     = 3.5    # Higher bar for per-process frequency (noisiest layer)
MIN_STDDEV           = 0.5

# Processes skipped entirely — normal background noise on any Linux system
ALWAYS_SAFE = {
    "systemd", "kthreadd", "kworker", "ksoftirqd", "migration",
    "rcu_sched", "rcu_bh", "watchdog", "kdevtmpfs", "netns",
    "khungtaskd", "kswapd0", "fsnotify_mark", "kthrotld", "irq",
    "sshd", "cron", "crond", "dbus-daemon", "NetworkManager",
    "agetty", "login", "sudo", "polkitd", "rsyslogd", "auditd",
    "snapd", "systemd-journal", "systemd-udevd", "systemd-resolve",
    "systemd-logind", "systemd-network", "systemd-timesyn",
    "udisksd", "ModemManager", "avahi-daemon", "bluetoothd",
    "thermald", "irqbalance", "accounts-daemon", "unattended-upgr",
    "apt", "apt-get", "dpkg", "dpkg-deb", "apt-cache",
    "bash", "sh", "zsh", "fish", "dash", "ksh",
    "bwrap", "xdg-dbus-proxy", "fusermount",
    "Xorg", "Xwayland", "gdm3", "gnome-shell", "plasmashell",
    "dconf-service", "gvfsd", "at-spi2-registryd",
    "gly-hdl-loader", "gly-shader-pre", "gpu-process",
    # Aegis-LX own processes — never flag ourselves
    "python3", "python", "iptables", "ip6tables", "cpulimit", "aegis",
}


class RollingStats:
    def __init__(self, maxlen=HISTORY_WINDOW):
        self.window = deque(maxlen=maxlen)

    def push(self, value):
        self.window.append(value)

    def mean(self):
        if not self.window:
            return 0.0
        return sum(self.window) / len(self.window)

    def stddev(self):
        if len(self.window) < 2:
            return MIN_STDDEV
        m = self.mean()
        variance = sum((x - m) ** 2 for x in self.window) / len(self.window)
        return max(math.sqrt(variance), MIN_STDDEV)

    def z_score(self, value):
        return (value - self.mean()) / self.stddev()

    def ready(self):
        return len(self.window) >= WARMUP_CYCLES


def _z_to_severity(z):
    if z >= 5.0:   return "CRITICAL"
    elif z >= 3.5: return "HIGH"
    elif z >= 2.5: return "MEDIUM"
    else:          return "LOW"


class StatEngine:
    def __init__(self):
        self.cycle_count   = 0
        self.proc_stats    = defaultdict(RollingStats)
        self.diversity     = RollingStats()
        self.velocity      = RollingStats()
        self.new_proc      = RollingStats()
        self.seen          = set()

    def observe(self, signals: list) -> dict:
        self.cycle_count += 1
        warming = self.cycle_count <= WARMUP_CYCLES

        freq = defaultdict(int)
        for s in signals:
            name = s.get("signal_type", "unknown")
            if any(name.startswith(safe) for safe in ALWAYS_SAFE):
                continue
            freq[name] += 1

        total    = sum(freq.values())
        unique   = len(freq)
        new_cnt  = len([p for p in freq if p not in self.seen])

        self.velocity.push(total)
        self.diversity.push(unique)
        self.new_proc.push(new_cnt)
        for proc, count in freq.items():
            self.proc_stats[proc].push(count)
        for proc in self.seen:
            if proc not in freq:
                self.proc_stats[proc].push(0)
        self.seen.update(freq.keys())

        report = {
            "cycle":        self.cycle_count,
            "warming_up":   warming,
            "anomalies":    [],
            "risk_level":   "LOW",
            "total_events": total,
            "unique_procs": unique,
        }

        if warming:
            left = WARMUP_CYCLES - self.cycle_count
            report["status"] = f"Warming up — {left} cycles left (~{left*10}s)"
            return report

        # Layer 1: Per-process frequency
        for proc, count in freq.items():
            s = self.proc_stats[proc]
            if not s.ready():
                continue
            z = s.z_score(count)
            if z > Z_THRESHOLD_FREQ:
                report["anomalies"].append({
                    "layer":    "FREQUENCY",
                    "process":  proc,
                    "detail":   f"'{proc}' ran {count}x (normal {s.mean():.1f}±{s.stddev():.1f}, Z={z:.1f})",
                    "severity": _z_to_severity(z),
                    "z_score":  round(z, 2),
                })

        # Layer 2: Diversity burst
        if self.diversity.ready():
            z = self.diversity.z_score(unique)
            if z > Z_THRESHOLD:
                report["anomalies"].append({
                    "layer":    "DIVERSITY_BURST",
                    "process":  None,
                    "detail":   f"{unique} unique procs (normal {self.diversity.mean():.1f}±{self.diversity.stddev():.1f}, Z={z:.1f})",
                    "severity": _z_to_severity(z),
                    "z_score":  round(z, 2),
                })

        # Layer 3: Velocity spike
        if self.velocity.ready():
            z = self.velocity.z_score(total)
            if z > Z_THRESHOLD:
                report["anomalies"].append({
                    "layer":    "VELOCITY_SPIKE",
                    "process":  None,
                    "detail":   f"{total} events (normal {self.velocity.mean():.1f}±{self.velocity.stddev():.1f}, Z={z:.1f})",
                    "severity": _z_to_severity(z),
                    "z_score":  round(z, 2),
                })

        # Layer 4: New/unseen process appearance
        if self.new_proc.ready() and new_cnt > 0:
            z = self.new_proc.z_score(new_cnt)
            if z > Z_THRESHOLD:
                new_names = [p for p in freq if p not in (self.seen - set(freq.keys()))]
                report["anomalies"].append({
                    "layer":    "NEW_PROCESS",
                    "process":  None,
                    "detail":   f"{new_cnt} unseen process(es): {new_names[:4]}",
                    "severity": "MEDIUM",
                    "z_score":  round(z, 2),
                })

        # Compute overall risk
        if not report["anomalies"]:
            report["risk_level"] = "LOW"
        else:
            sevs = [a["severity"] for a in report["anomalies"]]
            if "CRITICAL" in sevs or len(report["anomalies"]) >= 3:
                report["risk_level"] = "HIGH"
            elif "HIGH" in sevs or len(report["anomalies"]) >= 2:
                report["risk_level"] = "HIGH"
            elif "MEDIUM" in sevs:
                report["risk_level"] = "MEDIUM"
            else:
                report["risk_level"] = "LOW"

        report["status"] = "ACTIVE"
        return report
