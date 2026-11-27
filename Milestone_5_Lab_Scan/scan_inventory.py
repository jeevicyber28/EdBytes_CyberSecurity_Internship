"""Parse synthetic loopback scan fixtures and build defensive check prompts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PORT_LINE_RE = re.compile(r"^(\d+)/(\w+)\s+(open|closed|filtered)\s+(\S+)")


def parse_scan_text(text: str) -> dict:
    target = ""
    ports: list[dict] = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Target:"):
            target = stripped.split(":", 1)[1].strip()
            continue
        match = PORT_LINE_RE.match(stripped)
        if match:
            port_num, proto, state, service = match.groups()
            ports.append(
                {
                    "port": int(port_num),
                    "protocol": proto,
                    "state": state,
                    "service_label": service,
                }
            )

    open_ports = [p for p in ports if p["state"] == "open"]
    closed_ports = [p for p in ports if p["state"] == "closed"]

    defensive_checks = [
        f"Port {p['port']}/{p['protocol']} ({p['service_label']}): verify intended bind scope (127.0.0.1 vs 0.0.0.0) and vendor patch status."
        for p in open_ports
    ]

    return {
        "target": target,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "defensive_checks": defensive_checks,
        "disclaimer": "Open port or service label alone does not prove software version or vulnerability.",
    }


if __name__ == "__main__":
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("synthetic-scan.txt")
    print(json.dumps(parse_scan_text(source.read_text(encoding="utf-8")), indent=2))
