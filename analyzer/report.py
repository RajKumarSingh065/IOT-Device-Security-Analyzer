"""Assemble a structured report from a list of analyzed hosts."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .discovery import Host

GENERAL_RECOMMENDATIONS = [
    "Place IoT devices on a dedicated VLAN/SSID isolated from personal computers.",
    "Block outbound traffic from the IoT VLAN to the internet except for what each device needs.",
    "Change every device's default password to a unique, long passphrase stored in a password manager.",
    "Apply firmware updates monthly; retire devices the vendor no longer supports.",
    "Disable UPnP on your router unless a specific device actually requires it.",
    "Audit your network quarterly with this tool to catch newly-added devices or regressed configurations.",
]


def _host_dict(host: Host) -> dict[str, Any]:
    return {
        "ip": host.ip,
        "mac": host.mac,
        "hostname": host.hostname,
        "vendor": host.vendor,
        "open_ports": host.open_ports,
        "banners": host.banners,
        "findings": host.findings,
        "risk_score": host.risk_score,
        "risk_level": host.risk_level,
    }


def build_report(hosts: list[Host], subnet: str) -> dict[str, Any]:
    devices = [_host_dict(h) for h in hosts]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for h in hosts:
        for f in h.findings:
            sev = f.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1

    risk_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for h in hosts:
        risk_buckets[h.risk_level] = risk_buckets.get(h.risk_level, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subnet": subnet,
        "summary": {
            "devices_found": len(hosts),
            "findings_by_severity": severity_counts,
            "devices_by_risk_level": risk_buckets,
        },
        "devices": devices,
        "general_recommendations": GENERAL_RECOMMENDATIONS,
    }
