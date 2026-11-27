"""Minimal Python standard-library PCAP inspector for synthetic.pcap."""

from __future__ import annotations

import ipaddress
import json
import struct
import sys
from pathlib import Path

PCAP_MAGIC_LE = 0xA1B2C3D4


def decode_dns_qname(payload: bytes, offset: int = 12) -> str:
    labels: list[str] = []
    pos = offset
    while pos < len(payload):
        length = payload[pos]
        pos += 1
        if length == 0:
            break
        if pos + length > len(payload):
            break
        labels.append(payload[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels)


def parse_pcap(file_path: Path) -> list[dict]:
    raw = file_path.read_bytes()
    if len(raw) < 24:
        raise ValueError("File too small to contain a valid 24-byte PCAP global header.")

    magic = struct.unpack("<I", raw[:4])[0]
    if magic != PCAP_MAGIC_LE:
        raise ValueError(f"Unsupported PCAP magic header: 0x{magic:08x}")

    offset = 24
    packets: list[dict] = []
    frame_no = 0

    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack("<IIII", raw[offset : offset + 16])
        offset += 16
        frame_bytes = raw[offset : offset + incl_len]
        offset += incl_len
        frame_no += 1

        if len(frame_bytes) < 34:
            continue

        eth_type = struct.unpack("!H", frame_bytes[12:14])[0]
        if eth_type != 0x0800:
            continue

        ihl = (frame_bytes[14] & 0x0F) * 4
        proto = frame_bytes[23]
        src_ip = str(ipaddress.IPv4Address(frame_bytes[26:30]))
        dst_ip = str(ipaddress.IPv4Address(frame_bytes[30:34]))
        l4_start = 14 + ihl

        record: dict = {
            "frame": frame_no,
            "timestamp": f"{ts_sec}.{ts_usec:06d}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "length": incl_len,
        }

        if proto == 17 and len(frame_bytes) >= l4_start + 8:
            src_port, dst_port = struct.unpack("!HH", frame_bytes[l4_start : l4_start + 4])
            record.update({"transport": "UDP", "src_port": src_port, "dst_port": dst_port})
            app_data = frame_bytes[l4_start + 8 :]
            if dst_port == 53 or src_port == 53:
                record["protocol"] = "DNS"
                record["dns_query"] = decode_dns_qname(app_data)
        elif proto == 6 and len(frame_bytes) >= l4_start + 20:
            src_port, dst_port = struct.unpack("!HH", frame_bytes[l4_start : l4_start + 4])
            tcp_hdr_len = ((frame_bytes[l4_start + 12] >> 4) & 0x0F) * 4
            record.update({"transport": "TCP", "src_port": src_port, "dst_port": dst_port})
            app_data = frame_bytes[l4_start + tcp_hdr_len :]
            text = app_data.decode("ascii", errors="replace")
            if text.startswith(("GET ", "POST ", "HEAD ", "PUT ")):
                lines = text.split("\r\n")
                parts = lines[0].split(" ")
                record["protocol"] = "HTTP"
                record["http_method"] = parts[0] if len(parts) > 0 else ""
                record["http_path"] = parts[1] if len(parts) > 1 else ""
                host_line = next((ln for ln in lines[1:] if ln.lower().startswith("host:")), "")
                if host_line:
                    record["http_host"] = host_line.split(":", 1)[1].strip()

        packets.append(record)

    return packets


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("synthetic.pcap")
    print(json.dumps(parse_pcap(target), indent=2))
