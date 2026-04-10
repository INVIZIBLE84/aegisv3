# detection/signature_engine.py
"""
Signature Engine — Aegis-LX
=============================
Scores signals against the dictionary (raw_weight) and returns a
structured result including which kill chain phase was hit.
"""

from translator.signal_translator import (
    PHASE_SAFE, PHASE_RECON, PHASE_DISCOVERY, PHASE_CREDENTIAL,
    PHASE_EXECUTION, PHASE_PERSISTENCE, PHASE_EXFIL, PHASE_LATERAL
)

# Phase → minimum tier to trigger
PHASE_TIER_MAP = {
    PHASE_SAFE:        0,
    PHASE_RECON:       1,
    PHASE_DISCOVERY:   1,
    PHASE_CREDENTIAL:  3,
    PHASE_EXECUTION:   3,
    PHASE_PERSISTENCE: 3,
    PHASE_EXFIL:       4,
    PHASE_LATERAL:     4,
}


class SignatureEngine:
    def analyze(self, signals: list) -> dict:
        total_score  = 0
        hits         = []
        highest_tier = 0
        phases_seen  = set()

        for s in signals:
            w = s.get("raw_weight", 0)
            if w == 0:
                continue
            total_score += w
            phase = s.get("phase", PHASE_SAFE)
            phases_seen.add(phase)
            tier = PHASE_TIER_MAP.get(phase, 0)
            highest_tier = max(highest_tier, tier)
            hits.append({
                "process":  s["signal_type"],
                "phase":    phase,
                "weight":   w,
                "mitre":    s.get("mitre", ""),
                "full_cmd": s.get("context", {}).get("full_cmd", ""),
                "pid":      s.get("context", {}).get("pid"),
            })

        # Determine sig-based risk level from score
        if total_score >= 25:
            sig_risk = "HIGH"
        elif total_score >= 10:
            sig_risk = "MEDIUM"
        else:
            sig_risk = "LOW"

        return {
            "score":        total_score,
            "risk_level":   sig_risk,
            "hits":         hits,
            "phases":       list(phases_seen),
            "highest_tier": highest_tier,
        }
