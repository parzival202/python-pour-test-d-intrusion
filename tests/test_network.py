import unittest
from modules.network import scanner

class TestNetworkScanner(unittest.TestCase):
    def test_scan_localhost_returns_dict(self):
        res = scanner.scan_target("127.0.0.1")
        self.assertIsInstance(res, dict)
        self.assertIn("hosts_alive", res)
        self.assertIn("hosts_info", res)
        self.assertIn("meta", res)

if __name__ == "__main__":
    unittest.main()
