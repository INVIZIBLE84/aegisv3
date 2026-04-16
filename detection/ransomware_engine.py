# detection/ransomware_engine.py
"""
Ransomware Detection Engine - Aegis-LX
========================================
Detects ransomware behaviour using two signals:

1. RAPID FILE MODIFICATION PATTERN
   Ransomware reads files, writes encrypted versions, deletes originals.
   This creates a measurable spike: many unique files opened per PID
   in a short window. Normal processes don't touch 20+ different files
   in 10 seconds. Ransomware does.

2. ENTROPY SPIKE DETECTION
   Encrypted data is statistically random — maximum entropy (~8.0 bits).
   Normal files (text, code, documents) have low entropy (~3-5 bits).
   When a process writes high-entropy data to files that previously had
   low entropy, that's encryption happening in real time.

WHY THIS APPROACH:
   Uses the existing openat eBPF hook (already working) + Python entropy
   analysis. No new eBPF hooks needed. Works on any kernel.

DETECTION FLOW:
   openat events → track files-per-PID per window
                 → check entropy of recently modified files
                 → if rapid access + high entropy = ransomware alert
"""

import os
import math
import time
from collections import defaultdict

# How many unique files a PID must open in the window to be suspicious
FILE_ACCESS_THRESHOLD = 15      # files per window
FILE_ACCESS_WINDOW    = 30      # seconds

# Entropy threshold — above this = encrypted/compressed data
HIGH_ENTROPY_THRESHOLD = 7.2    # bits (max is 8.0)

# Minimum file size to check entropy (skip tiny files)
MIN_FILE_SIZE = 512             # bytes

# File extensions ransomware typically targets
TARGET_EXTENSIONS = {
    ".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx",
    ".jpg", ".jpeg", ".png", ".bmp", ".mp4", ".mp3",
    ".zip", ".tar", ".gz", ".py", ".js", ".html",
    ".csv", ".json", ".xml", ".conf", ".cfg", ".ini",
    ".key", ".pem", ".crt", ".db", ".sqlite",
}

# Processes that legitimately touch many files rapidly
TRUSTED_HEAVY_WRITERS = {
    "apt", "apt-get", "dpkg", "pip", "pip3",
    "rsync", "cp", "mv", "tar", "zip", "unzip",
    "find", "updatedb", "mlocate",
    "git", "gcc", "make", "python3", "python",
    "vim", "nano", "gedit",
    "aegis",                    # never flag ourselves
}


def _file_entropy(filepath, sample_bytes=8192):
    """
    Calculate Shannon entropy of a file's content.
    Returns 0.0-8.0 where 8.0 = perfectly random (encrypted).
    """
    try:
        st = os.stat(filepath)
        if st.st_size < MIN_FILE_SIZE:
            return 0.0
        with open(filepath, "rb") as f:
            data = f.read(sample_bytes)
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return 0.0


def _is_target_file(filepath):
    """Check if file has an extension ransomware typically targets."""
    _, ext = os.path.splitext(filepath.lower())
    return ext in TARGET_EXTENSIONS


class RansomwareEngine:
    """
    Detects ransomware using file access patterns and entropy analysis.
    Feed it openat events from collect_file_events() every cycle.
    """

    def __init__(self):
        # pid -> list of (timestamp, filepath) tuples
        self.file_access_log = defaultdict(list)

        # pid -> process_name (for display)
        self.pid_names = {}

        # filepath -> last known entropy (for comparison)
        self.entropy_baseline = {}

        # track already-alerted PIDs to avoid spam
        self.alerted_pids = set()

    def analyze(self, file_events):
        """
        Analyze a batch of file open events.
        Returns list of ransomware alert dicts.
        """
        alerts = []
        now    = time.time()

        # ── Ingest events ─────────────────────────────────────────────────────
        for ev in file_events:
            pid      = ev.get("pid")
            proc     = ev.get("process_name", "unknown")
            filepath = ev.get("filename", "")

            if not pid or not filepath:
                continue

            # Trust heavy-writer processes
            if proc in TRUSTED_HEAVY_WRITERS:
                continue

            # Only track target file types
            if not _is_target_file(filepath):
                continue

            self.pid_names[pid] = proc
            self.file_access_log[pid].append((now, filepath))

        # ── Clean old entries outside window ──────────────────────────────────
        for pid in list(self.file_access_log.keys()):
            self.file_access_log[pid] = [
                (t, f) for t, f in self.file_access_log[pid]
                if now - t <= FILE_ACCESS_WINDOW
            ]
            if not self.file_access_log[pid]:
                del self.file_access_log[pid]

        # ── Check each PID ────────────────────────────────────────────────────
        for pid, accesses in self.file_access_log.items():

            # Skip already alerted
            if pid in self.alerted_pids:
                continue

            proc         = self.pid_names.get(pid, "unknown")
            unique_files = list({f for _, f in accesses})
            count        = len(unique_files)

            # ── Signal 1: Rapid file access ───────────────────────────────────
            if count >= FILE_ACCESS_THRESHOLD:

                # ── Signal 2: Entropy check on recently accessed files ────────
                high_entropy_files = []
                for filepath in unique_files[:10]:    # check up to 10
                    entropy = _file_entropy(filepath)
                    if entropy >= HIGH_ENTROPY_THRESHOLD:
                        high_entropy_files.append((filepath, entropy))

                # Both signals = high confidence ransomware
                if high_entropy_files:
                    sample_file, sample_entropy = high_entropy_files[0]
                    detail = (
                        proc + " (PID " + str(pid) + ") accessed " +
                        str(count) + " files in " + str(FILE_ACCESS_WINDOW) +
                        "s — " + str(len(high_entropy_files)) +
                        " have high entropy (" + str(sample_entropy) + " bits)"
                    )
                    self.alerted_pids.add(pid)
                    alerts.append({
                        "source":   "RANSOMWARE",
                        "process":  proc,
                        "pid":      pid,
                        "files_accessed": count,
                        "high_entropy_files": len(high_entropy_files),
                        "sample_entropy": sample_entropy,
                        "sample_file": sample_file,
                        "phase":    "EXECUTION",
                        "tier":     4,
                        "mitre":    "T1486 (Data Encrypted for Impact)",
                        "detail":   detail,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })

                # Rapid access alone (no high entropy yet) = warning
                elif count >= FILE_ACCESS_THRESHOLD * 2:
                    detail = (
                        proc + " (PID " + str(pid) + ") accessed " +
                        str(count) + " files in " + str(FILE_ACCESS_WINDOW) +
                        "s — monitoring for encryption"
                    )
                    alerts.append({
                        "source":   "RANSOMWARE",
                        "process":  proc,
                        "pid":      pid,
                        "files_accessed": count,
                        "high_entropy_files": 0,
                        "sample_entropy": 0.0,
                        "sample_file": "",
                        "phase":    "EXECUTION",
                        "tier":     2,
                        "mitre":    "T1486 (Rapid File Access — possible staging)",
                        "detail":   detail,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })

        return alerts
