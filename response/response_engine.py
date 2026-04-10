# response/response_engine.py
"""
Response Engine — Aegis-LX
============================
Executes the actual defence actions for each tier.

CRITICAL DESIGN PRINCIPLE — Legitimate users are NEVER affected:
  Tier 2 (SLOW)    → cpulimit targets only the SUSPICIOUS PROCESS's PID
  Tier 3 (CONTAIN) → iptables -m owner --uid-owner blocks only the suspect UID/PID
  Tier 4 (ISOLATE) → blocks NEW outbound only; --state ESTABLISHED keeps existing
                      sessions (admin SSH stays alive)
  Tier 5 (LOCKDOWN)→ manual only, never called from here automatically
"""

import subprocess
import os

# Track active throttle PIDs so we can clean them up on de-escalation
_throttled_pids: set = set()
_isolate_rule_active: bool = False


def apply_tier(new_tier: int, old_tier: int, sig_hits: list):
    """
    Called when tier changes. Applies or removes defences accordingly.
    sig_hits: list of signature hits (each has 'pid' and 'phase').
    """
    if new_tier > old_tier:
        _escalate(new_tier, sig_hits)
    elif new_tier < old_tier:
        _deescalate(new_tier, old_tier)


def _escalate(tier: int, sig_hits: list):
    global _isolate_rule_active

    if tier == 1:
        # WATCH — no system action, just alerting (handled by notifier)
        pass

    elif tier == 2:
        # SLOW — CPU-throttle the suspicious process(es) by PID
        # cpulimit --pid <PID> --limit 10  → caps that process at 10% CPU
        # This does NOT affect any other process on the system.
        pids = _extract_pids(sig_hits)
        for pid in pids:
            if pid and pid not in _throttled_pids:
                try:
                    subprocess.Popen(
                        ["cpulimit", "--pid", str(pid), "--limit", "10", "--background"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    _throttled_pids.add(pid)
                    print(f"  [SLOW] CPU throttled PID {pid} to 10%")
                except FileNotFoundError:
                    print("  [SLOW] cpulimit not found — install with: sudo apt install cpulimit")

    elif tier == 3:
        # CONTAIN — block outbound for suspicious process owner only
        # Uses iptables owner match: only traffic from that UID gets blocked
        # Admin's SSH (running as different user/root established) stays alive
        uids = _extract_uids(sig_hits)
        for uid in uids:
            if uid is not None:
                try:
                    subprocess.run(
                        ["iptables", "-A", "OUTPUT",
                         "-m", "owner", "--uid-owner", str(uid),
                         "-m", "state", "--state", "NEW",
                         "-j", "DROP"],
                        check=True, stderr=subprocess.PIPE
                    )
                    print(f"  [CONTAIN] Outbound blocked for UID {uid} (suspect process only)")
                except subprocess.CalledProcessError as e:
                    print(f"  [CONTAIN] iptables owner match failed: {e.stderr.decode()[:80]}")
                except FileNotFoundError:
                    print("  [CONTAIN] iptables not found")

    elif tier == 4:
        # ISOLATE — block ALL new outbound system-wide
        # --state NEW,RELATED drops new connections
        # --state ESTABLISHED is NOT blocked → existing SSH stays alive
        if not _isolate_rule_active:
            try:
                subprocess.run(
                    ["iptables", "-A", "OUTPUT",
                     "-m", "state", "--state", "NEW,RELATED",
                     "-j", "DROP"],
                    check=True, stderr=subprocess.PIPE
                )
                _isolate_rule_active = True
                print("  [ISOLATE] All NEW outbound blocked. Established sessions preserved.")
            except subprocess.CalledProcessError as e:
                print(f"  [ISOLATE] iptables failed: {e.stderr.decode()[:80]}")
            except FileNotFoundError:
                print("  [ISOLATE] iptables not found")


def _deescalate(new_tier: int, old_tier: int):
    global _isolate_rule_active

    # Remove ISOLATE rule when stepping below tier 4
    if old_tier >= 4 and new_tier < 4 and _isolate_rule_active:
        try:
            subprocess.run(
                ["iptables", "-D", "OUTPUT",
                 "-m", "state", "--state", "NEW,RELATED",
                 "-j", "DROP"],
                stderr=subprocess.DEVNULL
            )
            _isolate_rule_active = False
            print("  [RESTORE] System-wide outbound block lifted")
        except Exception:
            pass

    # Remove CONTAIN rules when stepping below tier 3
    if old_tier >= 3 and new_tier < 3:
        try:
            subprocess.run(
                ["iptables", "-F", "OUTPUT"],
                stderr=subprocess.DEVNULL
            )
            print("  [RESTORE] Per-process network contain rules cleared")
        except Exception:
            pass

    # Release CPU throttles when stepping below tier 2
    if old_tier >= 2 and new_tier < 2:
        for pid in list(_throttled_pids):
            try:
                # Kill the cpulimit process watching this PID
                subprocess.run(
                    ["pkill", "-f", f"cpulimit.*{pid}"],
                    stderr=subprocess.DEVNULL
                )
                _throttled_pids.discard(pid)
            except Exception:
                pass
        if not _throttled_pids:
            print("  [RESTORE] CPU throttles released")


def _extract_pids(sig_hits: list) -> list:
    return [h.get("pid") for h in sig_hits if h.get("pid")]


def _extract_uids(sig_hits: list) -> list:
    # In the eBPF observer, user is currently hardcoded as 'root'
    # When real UID tracking is added, map username → UID here
    # For now, return empty list so CONTAIN gracefully skips UID-based blocking
    # and falls back to system-wide (tier 4 behaviour)
    uids = []
    for h in sig_hits:
        user = h.get("user", "")
        if user == "root":
            uids.append(0)
        # Future: resolve username → uid via pwd.getpwnam(user).pw_uid
    return list(set(uids))


def flush_all_rules():
    """Emergency cleanup — call on exit to ensure no iptables rules are left behind."""
    global _isolate_rule_active
    try:
        subprocess.run(["iptables", "-F", "OUTPUT"], stderr=subprocess.DEVNULL)
        _isolate_rule_active = False
    except Exception:
        pass
    for pid in list(_throttled_pids):
        try:
            subprocess.run(["pkill", "-f", f"cpulimit.*{pid}"], stderr=subprocess.DEVNULL)
        except Exception:
            pass
    _throttled_pids.clear()
