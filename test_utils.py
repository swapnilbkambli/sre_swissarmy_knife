import unittest
from utils import epoch_to_datetime, datetime_to_epoch, format_json, minify_json, base64_encode, base64_decode

class TestUtils(unittest.TestCase):
    def test_epoch_to_datetime(self):
        # Seconds
        res = epoch_to_datetime("1673952165")
        self.assertIn("2023-01-17", res["utc"])
        
        # Milliseconds
        res = epoch_to_datetime("1673952165000")
        self.assertIn("2023-01-17", res["utc"])

    def test_json_tools(self):
        raw = '{"a":1,"b":2}'
        beautified = format_json(raw)
        self.assertIn("\n    ", beautified)
        
        minified = minify_json(beautified)
        self.assertEqual(minified, raw)

    def test_base64_tools(self):
        plain = "hello world"
        encoded = base64_encode(plain)
        self.assertEqual(encoded, "aGVsbG8gd29ybGQ=")
        
        decoded = base64_decode(encoded)
        self.assertEqual(decoded, plain)

if __name__ == "__main__":
    unittest.main()
