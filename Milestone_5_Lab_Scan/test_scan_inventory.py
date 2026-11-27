import unittest
from pathlib import Path
from scan_inventory import parse_scan_text


class TestScanInventory(unittest.TestCase):
    def test_parses_synthetic_scan_fixture(self):
        scan_file = Path(__file__).with_name("synthetic-scan.txt")
        summary = parse_scan_text(scan_file.read_text(encoding="utf-8"))

        self.assertIn("127.0.0.1", summary["target"])
        self.assertEqual([p["port"] for p in summary["open_ports"]], [8765])
        self.assertEqual([p["port"] for p in summary["closed_ports"]], [22, 80])
        self.assertEqual(summary["open_ports"][0]["service_label"], "training-http")
        self.assertEqual(len(summary["defensive_checks"]), 1)

    def test_empty_input_returns_empty_lists(self):
        summary = parse_scan_text("")
        self.assertEqual(summary["open_ports"], [])
        self.assertEqual(summary["closed_ports"], [])


if __name__ == "__main__":
    unittest.main()
