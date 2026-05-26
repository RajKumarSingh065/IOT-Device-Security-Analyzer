"""Port scanner with banner grabbing, focused on common IoT services."""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports seen on IoT devices and what they typically indicate.
COMMON_IOT_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "https",
    554: "rtsp",          # IP cameras
    1883: "mqtt",         # MQTT broker (unencrypted)
    1900: "upnp-ssdp",    # UPnP discovery (UDP, but TCP often paired)
    5000: "upnp-http",    # UPnP description endpoint
    5683: "coap",         # Constrained Application Protocol
    7547: "tr-069",       # CWMP — historically abused (Mirai)
    8000: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8883: "mqtt-tls",
    9999: "telnet-alt",
    37777: "dahua-dvr",   # Dahua/Hikvision DVRs
    49152: "upnp",
}


def _probe_http(sock: socket.socket, host: str) -> str:
    req = (
        f"GET / HTTP/1.0\r\nHost: {host}\r\n"
        "User-Agent: IoT-Security-Analyzer/1.0\r\n\r\n"
    ).encode()
    sock.sendall(req)
    data = sock.recv(2048)
    return data.decode("utf-8", errors="replace").strip()


def _grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if port in (443, 8443, 8883):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    if port == 8883:
                        return "TLS handshake OK (MQTT-TLS)"
                    return _probe_http(ssock, host)

            if port in (80, 8000, 8080, 8081, 5000):
                return _probe_http(sock, host)

            # Plain banner-grab: many services emit a banner on connect.
            try:
                data = sock.recv(512)
                return data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                return ""
    except (OSError, ssl.SSLError) as exc:
        return f"[error: {exc.__class__.__name__}]"


def _check_port(host: str, port: int, timeout: float) -> tuple[int, str] | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        return None
    banner = _grab_banner(host, port, timeout=timeout)
    return port, banner


def scan_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.5,
    max_workers: int = 32,
) -> tuple[list[int], dict[int, str]]:
    ports = ports or list(COMMON_IOT_PORTS.keys())
    open_ports: list[int] = []
    banners: dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_check_port, host, p, timeout) for p in ports]
        for fut in as_completed(futures):
            result = fut.result()
            if result is None:
                continue
            port, banner = result
            open_ports.append(port)
            if banner:
                banners[port] = banner[:500]  # cap

    open_ports.sort()
    return open_ports, banners
