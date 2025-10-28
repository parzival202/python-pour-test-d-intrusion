import unittest
from modules.reconnaissance import passive

class TestPassiveRecon(unittest.TestCase):
    def test_passive_aggregate_basic(self):
        res = passive.passive_aggregate("127.0.0.1")
        self.assertIsInstance(res, dict)
        self.assertIn("host_info", res)

if __name__ == "__main__":
    unittest.main()
