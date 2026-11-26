# Python 3 standard library; dummy values only.
# Extended local experiment based on the untouched starter hash-demo.py.
import hashlib
import hmac
import secrets


def derive_hash(value: bytes, salt: bytes, iterations: int = 100_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", value, salt, iterations)


def main() -> None:
    dummy_password = b"dummy-practice-value"

    salt_1 = secrets.token_bytes(16)
    salt_2 = secrets.token_bytes(16)

    hash_1 = derive_hash(dummy_password, salt_1)
    hash_2 = derive_hash(dummy_password, salt_2)

    print("=== Starter Checks (Dummy Data Only) ===")
    print("Different salts:", salt_1 != salt_2)
    print("Different hashes:", hash_1 != hash_2)
    print("Correct value:", hmac.compare_digest(hash_1, derive_hash(dummy_password, salt_1)))
    print("Wrong value:", hmac.compare_digest(hash_1, derive_hash(b"wrong-dummy", salt_1)))

    print("\n=== Observed Random Salts & Derived PBKDF2-SHA256 Hashes ===")
    print(f"Salt 1 (hex): {salt_1.hex()}")
    print(f"Hash 1 (hex): {hash_1.hex()}")
    print(f"Salt 2 (hex): {salt_2.hex()}")
    print(f"Hash 2 (hex): {hash_2.hex()}")

    print("\n=== Boundary & Failure Cases ===")
    empty_check = hmac.compare_digest(hash_1, derive_hash(b"", salt_1))
    case_check = hmac.compare_digest(hash_1, derive_hash(b"Dummy-Practice-Value", salt_1))
    wrong_salt_check = hmac.compare_digest(hash_1, derive_hash(dummy_password, salt_2))
    print("Empty input matches:", empty_check)
    print("Case-mismatch matches:", case_check)
    print("Correct dummy value with wrong salt matches:", wrong_salt_check)


if __name__ == "__main__":
    main()
