import unittest
from modules.web import crawler

class TestWebCrawler(unittest.TestCase):
    def test_crawl_localhost_structure(self):
        # depth=0 to be fast — only fetch the seed
        res = crawler.crawl("http://127.0.0.1", depth=0)
        self.assertIsInstance(res, dict)
        self.assertIn("pages_scanned", res)
        self.assertIn("forms_found", res)

if __name__ == "__main__":
    unittest.main()
