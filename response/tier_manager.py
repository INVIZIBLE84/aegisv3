# response/tier_manager.py
"""
Tier Manager — Aegis-LX
=========================
Manages the 5-tier graduated response system.

TIERS:
  0  NORMAL    → observe only
  1  WATCH     → alert sent, no disruption
  2  SLOW      → suspect process CPU-throttled (PID-targeted)
  3  CONTAIN   → suspect process network-blocked (PID-targeted, NOT system-wide)
  4  ISOLATE   → all NEW outbound blocked (established connections preserved)
  5  LOCKDOWN  → MANUAL ONLY — never triggers automatically

ESCALATION LOGIC:
  - Instant escalation up based on threat signals
  - Graduated de-escalation: one tier at a time, after cooldown
  - Two signals from DIFFERENT kill chain phases = escalate one extra tier
  - Tier 5 requires explicit human command — never auto-triggers

COOLDOWN TABLE (seconds of clean cycles before stepping down):
  4→3 : 300s  (5 min)
  3→2 : 240s  (4 min)
  2→1 : 180s  (3 min)
  1→0 : 120s  (2 min)
"""

import time

TIER_NAMES = {
    0: "NORMAL",
    1: "WATCH",
    2: "SLOW",
    3: "CONTAIN",
    4: "ISOLATE",
    5: "LOCKDOWN",
}

TIER_COLORS = {
    0: "\033[92m",   # Green
    1: "\033[96m",   # Cyan
    2: "\033[93m",   # Yellow
    3: "\033[33m",   # Orange-ish
    4: "\033[91m",   # Red
    5: "\033[95m",   # Magenta
}

COOLDOWNS = {4: 300, 3: 240, 2: 180, 1: 120}

# Map risk level + phase combo → recommended tier
RISK_TO_TIER = {
    ("LOW",    "SAFE"):        0,
    ("LOW",    "RECON"):       1,
    ("MEDIUM", "RECON"):       1,
    ("MEDIUM", "DISCOVERY"):   2,
    ("HIGH",   "RECON"):       2,
    ("MEDIUM", "CREDENTIAL"):  3,
    ("HIGH",   "DISCOVERY"):   2,
    ("HIGH",   "CREDENTIAL"):  3,
    ("HIGH",   "EXECUTION"):   3,
    ("HIGH",   "PERSISTENCE"): 3,
    ("HIGH",   "EXFILTRATION"):4,
    ("HIGH",   "LATERAL"):     4,
}


class TierManager:
    def __init__(self):
        self.current          = 0
        self.last_threat_time = time.time()
        self.lockdown_manual  = False   # Only True if human explicitly typed it
        self.threat_history   = []      # Recent phases seen, for multi-phase escalation

    @property
    def name(self):
        return TIER_NAMES[self.current]

    @property
    def color(self):
        return TIER_COLORS[self.current]

    def evaluate(self, stat_report: dict, sig_result: dict) -> dict:
        """
        Given detection results, decide what tier we should be at.
        Returns a change_report dict.
        """
        if self.lockdown_manual:
            return self._no_change("LOCKDOWN is manual — awaiting human release")

        now             = time.time()
        stat_risk       = stat_report.get("risk_level", "LOW")
        sig_risk        = sig_result.get("risk_level", "LOW")
        phases          = sig_result.get("phases", [])
        sig_tier        = sig_result.get("highest_tier", 0)
        warming_up      = stat_report.get("warming_up", False)

        # During warm-up, only act on strong signature hits
        if warming_up:
            if sig_tier >= 4:
                return self._escalate_to(4, "Exfiltration/Lateral signature during warm-up", now)
            elif sig_tier >= 3:
                return self._escalate_to(3, "Execution/Credential signature during warm-up", now)
            return self._maybe_deescalate(now)

        # ── Determine recommended tier ────────────────────────────────────────

        # Combine stat and sig risk (take the higher)
        combined_risk = self._higher_risk(stat_risk, sig_risk)

        # Base tier from risk + most severe phase
        worst_phase   = self._worst_phase(phases)
        lookup_key    = (combined_risk, worst_phase)
        recommended   = RISK_TO_TIER.get(lookup_key, 0)

        # Also consider the sig engine's direct tier suggestion
        recommended   = max(recommended, sig_tier if combined_risk != "LOW" else 0)

        # Multi-phase escalation bonus: if attacker is hitting 2+ different phases
        # it means they are progressing through the kill chain — escalate one extra tier
        if phases:
            self.threat_history.extend(phases)
            self.threat_history = self.threat_history[-20:]   # Keep last 20
            unique_recent = len(set(self.threat_history))
            if unique_recent >= 3 and recommended < 4:
                recommended += 1

        # Cap at 4 — Tier 5 is manual only
        recommended = min(recommended, 4)

        if recommended > self.current:
            reason = f"{combined_risk} risk | Phase: {worst_phase} | Sig score: {sig_result['score']}"
            return self._escalate_to(recommended, reason, now)
        else:
            return self._maybe_deescalate(now)

    def manual_lockdown(self, reason="Operator initiated"):
        old = self.current
        self.current       = 5
        self.lockdown_manual = True
        return self._change_report(old, 5, reason)

    def manual_release(self):
        """Human explicitly releases lockdown."""
        if not self.lockdown_manual:
            return self._no_change("Not in manual lockdown")
        self.lockdown_manual  = False
        self.current          = 4       # Step to ISOLATE, not straight to NORMAL
        self.last_threat_time = time.time()
        return self._change_report(5, 4, "Manual release by operator — stepping to ISOLATE")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _escalate_to(self, target, reason, now):
        old = self.current
        self.current          = target
        self.last_threat_time = now
        return self._change_report(old, target, reason)

    def _maybe_deescalate(self, now=None):
        if now is None:
            now = time.time()
        elapsed = now - self.last_threat_time
        cooldown = COOLDOWNS.get(self.current, 999)

        if self.current > 0 and elapsed > cooldown:
            old = self.current
            self.current -= 1
            return self._change_report(
                old, self.current,
                f"Clean for {int(elapsed)}s — stepping down"
            )
        return self._no_change()

    def _change_report(self, old, new, reason=""):
        return {
            "changed":   old != new,
            "old_tier":  old,
            "old_name":  TIER_NAMES[old],
            "new_tier":  new,
            "new_name":  TIER_NAMES[new],
            "direction": "UP" if new > old else "DOWN",
            "reason":    reason,
        }

    def _no_change(self, reason=""):
        return {
            "changed":   False,
            "old_tier":  self.current,
            "old_name":  TIER_NAMES[self.current],
            "new_tier":  self.current,
            "new_name":  TIER_NAMES[self.current],
            "direction": "NONE",
            "reason":    reason,
        }

    def _higher_risk(self, a, b):
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        return a if order.get(a, 0) >= order.get(b, 0) else b

    def _worst_phase(self, phases):
        priority = {
            "EXFILTRATION": 7, "LATERAL": 6, "PERSISTENCE": 5,
            "EXECUTION": 4, "CREDENTIAL": 3, "DISCOVERY": 2,
            "RECON": 1, "SAFE": 0,
        }
        if not phases:
            return "SAFE"
        return max(phases, key=lambda p: priority.get(p, 0))
