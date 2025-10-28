import unittest
from modules.web import scanner

class TestWebScanner(unittest.TestCase):
    def test_scan_page_structure(self):
        # fast test against localhost (may return empty results but structure must be dict)
        res = scanner.scan_page("http://127.0.0.1", timeout=2)
        self.assertIsInstance(res, dict)
        self.assertIn("xss", res)
        self.assertIn("sqli", res)
        self.assertIn("lfi", res)

if __name__ == "__main__":
    unittest.main()
