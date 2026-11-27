import tempfile
import unittest
from pathlib import Path
from pcap_inspector import parse_pcap


class TestPcapInspector(unittest.TestCase):
    def test_synthetic_pcap_extracts_dns_and_http(self):
        pcap_file = Path(__file__).with_name("synthetic.pcap")
        packets = parse_pcap(pcap_file)
        self.assertEqual(len(packets), 2)

        dns_pkt = packets[0]
        self.assertEqual(dns_pkt["protocol"], "DNS")
        self.assertEqual(dns_pkt["dns_query"], "training.example")
        self.assertEqual(dns_pkt["src_ip"], "192.0.2.10")
        self.assertEqual(dns_pkt["dst_ip"], "192.0.2.20")

        http_pkt = packets[1]
        self.assertEqual(http_pkt["protocol"], "HTTP")
        self.assertEqual(http_pkt["http_method"], "GET")
        self.assertEqual(http_pkt["http_path"], "/practice")
        self.assertEqual(http_pkt["http_host"], "training.example")

    def test_invalid_magic_header_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.pcap"
            bad.write_bytes(b"\x00" * 32)
            with self.assertRaises(ValueError):
                parse_pcap(bad)


if __name__ == "__main__":
    unittest.main()
