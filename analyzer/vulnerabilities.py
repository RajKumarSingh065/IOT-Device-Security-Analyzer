"""Detect common IoT security issues from open-port / banner data.

This module is intentionally **non-intrusive**: it only inspects what the port
scanner already observed. It does NOT attempt credential brute-forcing or
exploit delivery.
"""
from __future__ import annotations

import re

# Service-level rules: presence of an open port that is inherently risky.
RISKY_SERVICES: dict[int, dict] = {
    21: {
        "id": "ftp-exposed",
        "title": "FTP service exposed",
        "severity": "high",
        "description": (
            "FTP transmits credentials and data in cleartext. Many IoT FTP "
            "daemons ship with default or anonymous logins."
        ),
        "recommendation": "Disable FTP or replace with SFTP/SCP over SSH.",
    },
    23: {
        "id": "telnet-exposed",
        "title": "Telnet service exposed",
        "severity": "critical",
        "description": (
            "Telnet has no encryption and is the #1 vector for IoT botnets "
            "(Mirai, Mozi). Many cameras/DVRs ship with telnet:root enabled."
        ),
        "recommendation": "Disable Telnet immediately; use SSH (port 22).",
    },
    1883: {
        "id": "mqtt-cleartext",
        "title": "Unencrypted MQTT broker",
        "severity": "medium",
        "description": (
            "MQTT on 1883 is unencrypted. Sensor data and commands can be "
            "intercepted; misconfigured brokers often allow anonymous publish."
        ),
        "recommendation": "Use MQTT-over-TLS on 8883 with authentication.",
    },
    5000: {
        "id": "upnp-exposed",
        "title": "UPnP HTTP endpoint exposed",
        "severity": "medium",
        "description": (
            "UPnP description endpoints have historically been abused to map "
            "router ports and pivot into networks (CallStranger, etc.)."
        ),
        "recommendation": "Disable UPnP on the router and on the device.",
    },
    7547: {
        "id": "tr069-exposed",
        "title": "TR-069 / CWMP exposed",
        "severity": "high",
        "description": (
            "TR-069 was the entry point for the 2016 Deutsche Telekom Mirai "
            "outbreak. It should never be exposed to the LAN clients."
        ),
        "recommendation": "Block TCP/7547 at the firewall; disable in CPE.",
    },
    9999: {
        "id": "telnet-alt-exposed",
        "title": "Non-standard Telnet port (9999) open",
        "severity": "high",
        "description": "Many IoT vendors hide a Telnet shell on 9999.",
        "recommendation": "Disable the service or block at the firewall.",
    },
    37777: {
        "id": "dahua-dvr-exposed",
        "title": "Dahua/Hikvision DVR control port exposed",
        "severity": "high",
        "description": (
            "Port 37777 is the proprietary control channel for Dahua-family "
            "DVRs and has a long history of authentication-bypass CVEs."
        ),
        "recommendation": (
            "Apply latest vendor firmware, change default credentials, and "
            "restrict access to a management VLAN."
        ),
    },
}

# Banner regex patterns -> finding template.
BANNER_PATTERNS: list[tuple[re.Pattern, dict]] = [
    (
        re.compile(r"Server:\s*Boa/0\.94", re.I),
        {
            "id": "boa-eol-webserver",
            "title": "End-of-life Boa web server",
            "severity": "high",
            "description": (
                "Boa httpd has been unmaintained since 2005 and is associated "
                "with multiple CVEs (Microsoft attributed it to the 2022 EV "
                "charger / building-automation attacks)."
            ),
            "recommendation": "Replace firmware or isolate the device.",
        },
    ),
    (
        re.compile(r"Server:\s*GoAhead", re.I),
        {
            "id": "goahead-webserver",
            "title": "GoAhead web server detected",
            "severity": "medium",
            "description": (
                "GoAhead older than 5.1.2 has authentication-bypass and RCE "
                "CVEs (CVE-2017-17562, CVE-2021-42342)."
            ),
            "recommendation": "Verify firmware version; update if available.",
        },
    ),
    (
        re.compile(r"Server:\s*Router\s*Webserver", re.I),
        {
            "id": "generic-router-webserver",
            "title": "Generic 'Router Webserver' banner",
            "severity": "low",
            "description": (
                "This banner is shared by many low-cost SOHO routers known to "
                "have weak default credentials."
            ),
            "recommendation": "Ensure default admin credentials are changed.",
        },
    ),
    (
        re.compile(r"Basic realm=", re.I),
        {
            "id": "http-basic-auth",
            "title": "HTTP Basic authentication in use",
            "severity": "low",
            "description": (
                "Basic-auth credentials are sent base64-encoded — effectively "
                "cleartext over HTTP. On port 80 this is risky on shared LANs."
            ),
            "recommendation": "Move admin UI to HTTPS and use form-based auth.",
        },
    ),
    (
        re.compile(r"220.*(?:vsftpd|ProFTPD|Pure-FTPd).*", re.I),
        {
            "id": "ftp-banner-leak",
            "title": "FTP banner reveals server software",
            "severity": "low",
            "description": "Banner exposes server vendor/version for targeted attacks.",
            "recommendation": "Disable FTP banner or move to SFTP.",
        },
    ),
    (
        re.compile(r"SSH-1\.", re.I),
        {
            "id": "ssh1-protocol",
            "title": "SSH protocol 1.x in use",
            "severity": "high",
            "description": (
                "SSHv1 has cryptographic weaknesses and has been deprecated "
                "since the early 2000s."
            ),
            "recommendation": "Configure SSHv2-only and update firmware.",
        },
    ),
    (
        re.compile(r"OpenSSH_[1-6]\.", re.I),
        {
            "id": "openssh-old",
            "title": "Outdated OpenSSH version",
            "severity": "medium",
            "description": "OpenSSH < 7.0 has several disclosed vulnerabilities.",
            "recommendation": "Update firmware to a build with OpenSSH >= 8.x.",
        },
    ),
]


def assess_device(open_ports: list[int], banners: dict[int, str]) -> list[dict]:
    findings: list[dict] = []
    seen_ids: set[str] = set()

    def _add(finding: dict, port: int | None = None):
        if finding["id"] in seen_ids:
            return
        seen_ids.add(finding["id"])
        entry = {**finding}
        if port is not None:
            entry["port"] = port
        findings.append(entry)

    for port in open_ports:
        if port in RISKY_SERVICES:
            _add(RISKY_SERVICES[port], port=port)

    for port, banner in banners.items():
        for pattern, template in BANNER_PATTERNS:
            if pattern.search(banner):
                _add(template, port=port)

    # Composite: many open ports => attack surface concern.
    if len(open_ports) >= 6:
        _add(
            {
                "id": "wide-attack-surface",
                "title": f"Wide attack surface ({len(open_ports)} ports open)",
                "severity": "medium",
                "description": (
                    "A device exposing many services to the LAN increases the "
                    "blast radius if any single one is compromised."
                ),
                "recommendation": (
                    "Disable unused services; segment the device onto an "
                    "IoT-only VLAN with restricted egress."
                ),
            }
        )

    # If the device is using cleartext admin (HTTP) AND has telnet/ftp, flag combo.
    cleartext_admin = any(p in open_ports for p in (80, 8080, 8000, 8081))
    cleartext_shell = any(p in open_ports for p in (21, 23, 9999))
    if cleartext_admin and cleartext_shell:
        _add(
            {
                "id": "all-cleartext-management",
                "title": "All management interfaces are cleartext",
                "severity": "high",
                "description": (
                    "Both the web UI and the shell are unencrypted. Anyone on "
                    "the same Wi-Fi can sniff credentials."
                ),
                "recommendation": (
                    "Enable HTTPS for the admin UI and SSH for remote shell; "
                    "disable HTTP and Telnet."
                ),
            }
        )

    return findings
