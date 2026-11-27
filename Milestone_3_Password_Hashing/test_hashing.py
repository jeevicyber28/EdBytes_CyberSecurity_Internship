import unittest
import hmac
from hashing_experiment import derive_hash


class TestSaltedHashing(unittest.TestCase):
    def test_unique_salts_produce_unique_digests(self):
        value = b"dummy-practice-value"
        salt_a = b"\x01" * 16
        salt_b = b"\x02" * 16
        self.assertNotEqual(derive_hash(value, salt_a), derive_hash(value, salt_b))

    def test_valid_and_invalid_candidates(self):
        salt = b"\xaa" * 16
        stored = derive_hash(b"dummy-practice-value", salt)
        self.assertTrue(hmac.compare_digest(stored, derive_hash(b"dummy-practice-value", salt)))
        self.assertFalse(hmac.compare_digest(stored, derive_hash(b"wrong-dummy", salt)))
        self.assertFalse(hmac.compare_digest(stored, derive_hash(b"", salt)))
        self.assertFalse(hmac.compare_digest(stored, derive_hash(b"Dummy-Practice-Value", salt)))


if __name__ == "__main__":
    unittest.main()
