"""Per-device risk scoring."""
from __future__ import annotations

SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 3,
}


def score_device(findings: list[dict], open_ports: list[int]) -> tuple[int, str]:
    score = 0
    for f in findings:
        score += SEVERITY_WEIGHT.get(f.get("severity", "low"), 3)

    # Small additional surface penalty (already partially covered by a finding,
    # but every extra port adds a sliver of risk).
    score += min(len(open_ports), 10)

    score = min(score, 100)
    if score >= 60:
        level = "critical"
    elif score >= 35:
        level = "high"
    elif score >= 15:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "informational"
    return score, level
