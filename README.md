# IoT Device Security Analyzer

A tool that analyzes and secures Internet of Things (IoT) devices within a
network, identifying vulnerabilities and providing recommendations for
improving security.

## What it does

- **Network discovery** — finds live hosts on your subnet via ARP (when run as
  admin) or an ICMP ping sweep with ARP-table reconciliation.
- **Port + banner scan** — checks a curated set of IoT-relevant TCP ports
  (Telnet, FTP, HTTP/HTTPS, RTSP, MQTT, UPnP, CoAP, TR-069, DVR control) and
  grabs service banners.
- **Vulnerability checks** — flags risky services (cleartext shells, exposed
  TR-069, unencrypted MQTT) and outdated software (Boa, old GoAhead, SSHv1,
  old OpenSSH) without performing intrusive credential testing.
- **Vendor fingerprinting** — maps MAC addresses to manufacturer using a
  curated OUI list focused on common IoT brands (extensible via
  [`data/oui.txt`](data/oui.txt)).
- **Risk report** — per-device risk score plus prioritized fixes and general
  network-hardening recommendations. Exportable as JSON.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Then open <http://127.0.0.1:5000>. The UI binds to localhost only.

On Windows, running PowerShell *as Administrator* enables the scapy ARP scan
(more accurate than ping sweep on devices that drop ICMP). On Linux/macOS use
`sudo`.

## Project layout

- [app.py](app.py) — Flask routes and the background scan worker
- [analyzer/discovery.py](analyzer/discovery.py) — host discovery
- [analyzer/port_scanner.py](analyzer/port_scanner.py) — TCP scan + banners
- [analyzer/vulnerabilities.py](analyzer/vulnerabilities.py) — detection rules
- [analyzer/fingerprint.py](analyzer/fingerprint.py) — MAC vendor lookup
- [analyzer/risk.py](analyzer/risk.py) — risk scoring
- [analyzer/report.py](analyzer/report.py) — report assembly
- [templates/](templates/), [static/style.css](static/style.css) — web UI

## Scope and ethics

Run this only on networks you own or have explicit written permission to
test. The tool is **non-intrusive by design**: it inspects what services
already expose and does not attempt credential brute-forcing or exploit
delivery.
