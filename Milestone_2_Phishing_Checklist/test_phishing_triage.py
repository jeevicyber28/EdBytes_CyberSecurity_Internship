import unittest
from phishing_triage import analyze_message, inspect_url


class TestPhishingTriage(unittest.TestCase):
    def test_synthetic_credential_lure_flags_indicators(self):
        res = analyze_message(
            subject="Urgent campus notice",
            body="Reset your password immediately via the link below.",
            urls=["http://college-login.example.invalid/login"],
        )
        self.assertEqual(res["verdict"], "review_out_of_band")
        self.assertGreaterEqual(res["indicator_count"], 3)

    def test_risky_attachment_flagged(self):
        res = analyze_message(
            subject="Invoice",
            body="See attached file.",
            attachments=["invoice_2026.docm"],
        )
        self.assertEqual(res["verdict"], "review_out_of_band")
        self.assertTrue(any("attachment" in item for item in res["indicators"]))

    def test_ip_literal_url_flagged(self):
        flags = inspect_url("http://192.0.2.10/login")
        self.assertTrue(any("raw IP literal" in f for f in flags))

    def test_ordinary_https_notice_has_no_red_flags(self):
        res = analyze_message(
            subject="Semester timetable posted",
            body="Check the official notice board on campus.",
            urls=["https://portal.university.edu/timetable"],
        )
        self.assertEqual(res["verdict"], "no_obvious_red_flags")
        self.assertEqual(res["indicator_count"], 0)


if __name__ == "__main__":
    unittest.main()
