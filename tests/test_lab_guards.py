import unittest
from lab.live import require_loopback


class LabBoundaryTests(unittest.TestCase):
    def test_external_or_credential_bearing_urls_are_rejected(self):
        for url in ("https://example.com:6443", "https://127.0.0.1.attacker.example", "https://user:password@localhost:6443"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                require_loopback(url)

    def test_loopback_endpoints_are_accepted(self):
        for url in ("https://127.0.0.1:16443", "https://localhost:16443", "https://[::1]:16443"):
            require_loopback(url)
