"""Flask web UI for the IoT Device Security Analyzer.

Run with:
    python app.py
Then open http://127.0.0.1:5000 in a browser.
"""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, redirect, render_template, request, url_for

from analyzer import (
    COMMON_IOT_PORTS,
    assess_device,
    build_report,
    detect_local_subnet,
    discover_hosts,
    lookup_vendor,
    scan_ports,
    score_device,
)

app = Flask(__name__)

# In-memory scan store. For a single-user local tool this is fine; do not use
# in a multi-tenant deployment.
SCANS: dict[str, dict] = {}
SCANS_LOCK = threading.Lock()


def _run_scan(scan_id: str, subnet: str, port_timeout: float) -> None:
    state = SCANS[scan_id]
    state["status"] = "discovering"
    started = time.time()

    hosts = discover_hosts(subnet)
    state["status"] = "scanning"
    state["progress"] = {"total": len(hosts), "completed": 0}

    def analyze(host):
        host.vendor = lookup_vendor(host.mac)
        host.open_ports, host.banners = scan_ports(
            host.ip, timeout=port_timeout
        )
        host.findings = assess_device(host.open_ports, host.banners)
        host.risk_score, host.risk_level = score_device(
            host.findings, host.open_ports
        )
        with SCANS_LOCK:
            state["progress"]["completed"] += 1
        return host

    # Scan multiple hosts in parallel, but keep concurrency modest to avoid
    # saturating cheap home routers.
    with ThreadPoolExecutor(max_workers=8) as pool:
        hosts = list(pool.map(analyze, hosts))

    # Order by risk descending, then IP ascending
    hosts.sort(key=lambda h: (-h.risk_score, h.ip))
    report = build_report(hosts, subnet)
    report["duration_seconds"] = round(time.time() - started, 1)

    with SCANS_LOCK:
        state["report"] = report
        state["status"] = "complete"


@app.route("/")
def index():
    return render_template(
        "index.html",
        default_subnet=detect_local_subnet(),
        port_count=len(COMMON_IOT_PORTS),
    )


@app.route("/scan", methods=["POST"])
def start_scan():
    subnet = request.form.get("subnet", "").strip() or detect_local_subnet()
    try:
        port_timeout = float(request.form.get("timeout", "1.5"))
    except ValueError:
        port_timeout = 1.5
    port_timeout = max(0.2, min(port_timeout, 10.0))

    scan_id = uuid.uuid4().hex[:12]
    with SCANS_LOCK:
        SCANS[scan_id] = {
            "id": scan_id,
            "subnet": subnet,
            "status": "queued",
            "progress": {"total": 0, "completed": 0},
            "report": None,
        }
    threading.Thread(
        target=_run_scan,
        args=(scan_id, subnet, port_timeout),
        daemon=True,
    ).start()
    return redirect(url_for("scan_view", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_view(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        return redirect(url_for("index"))
    return render_template("results.html", scan=state)


@app.route("/api/scan/<scan_id>")
def scan_status(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        return jsonify({"error": "not found"}), 404
    return jsonify(state)


@app.route("/api/scan/<scan_id>/report")
def scan_report(scan_id: str):
    state = SCANS.get(scan_id)
    if not state or not state.get("report"):
        return jsonify({"error": "not ready"}), 404
    return jsonify(state["report"])


if __name__ == "__main__":
    # Bind only to localhost — this tool surfaces network detail and should
    # not be reachable from the rest of the LAN.
    app.run(host="127.0.0.1", port=5000, debug=False)
