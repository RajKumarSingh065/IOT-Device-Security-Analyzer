"""Network discovery: find live hosts on the local subnet.

Two strategies:
  1. scapy ARP scan (accurate, requires admin/root)
  2. Concurrent ping sweep + ARP-table parsing (works without privileges)
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class Host:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "unknown"


def detect_local_subnet() -> str:
    """Return a best-guess /24 subnet for the active interface (e.g. '192.168.1.0/24')."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_interface(f"{local_ip}/24").network
        return str(net)
    except OSError:
        return "192.168.1.0/24"


def _ping(ip: str, timeout_ms: int = 500) -> bool:
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 1
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _read_arp_table() -> dict[str, str]:
    """Parse the OS ARP table into an {ip: mac} mapping."""
    mapping: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return mapping

    mac_re = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
    ip_re = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
    for line in out.splitlines():
        ip_match = ip_re.search(line)
        mac_match = mac_re.search(line)
        if ip_match and mac_match:
            ip = ip_match.group(0)
            mac = mac_match.group(0).replace("-", ":").lower()
            if mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("00:00:00"):
                mapping[ip] = mac
    return mapping


def _reverse_dns(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror):
        return None


def _scapy_arp_scan(subnet: str, timeout: int = 2) -> list[Host]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except ImportError:
        return []

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=timeout,
            verbose=False,
        )
    except (PermissionError, OSError):
        return []

    hosts = []
    for _, rcv in ans:
        hosts.append(Host(ip=rcv.psrc, mac=rcv.hwsrc.lower()))
    return hosts


def discover_hosts(subnet: str | None = None, max_workers: int = 64) -> list[Host]:
    subnet = subnet or detect_local_subnet()
    network = ipaddress.ip_network(subnet, strict=False)

    # 1) Try scapy ARP scan first (most accurate)
    scapy_hosts = _scapy_arp_scan(subnet)
    if scapy_hosts:
        for h in scapy_hosts:
            h.hostname = _reverse_dns(h.ip)
        return scapy_hosts

    # 2) Fallback: ping sweep + ARP table read
    addresses: Iterable[str] = (str(ip) for ip in network.hosts())
    live_ips: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping, ip): ip for ip in addresses}
        for fut in as_completed(futures):
            if fut.result():
                live_ips.append(futures[fut])

    arp_map = _read_arp_table()
    # The ARP table may also include hosts that didn't respond to ICMP (firewalled).
    for ip in arp_map:
        try:
            if ipaddress.ip_address(ip) in network and ip not in live_ips:
                live_ips.append(ip)
        except ValueError:
            continue

    hosts = []
    for ip in sorted(live_ips, key=lambda x: ipaddress.ip_address(x)):
        hosts.append(
            Host(ip=ip, mac=arp_map.get(ip), hostname=_reverse_dns(ip))
        )
    return hosts
