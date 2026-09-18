"""bcrypt password hashing: the built-in implementation, the policy and hash upgrades."""
import random
import unittest
from unittest import mock

from helpers import reset_process_state
from wol import bcrypt_py, passwords

try:
    import bcrypt as native
except ImportError:
    native = None


class BuiltinBcryptTest(unittest.TestCase):
    def test_blowfish_tables_are_the_digits_of_pi(self):
        p, s = bcrypt_py._initial_state()
        self.assertEqual(p[:4], [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344])
        self.assertEqual(p[17], 0x8979FB1B)
        self.assertEqual(s[0][0], 0xD1310BA6)
        self.assertEqual(s[3][255], 0x3AC372E6)

    def test_published_vectors(self):
        # OpenBSD / jBCrypt test vectors.
        vectors = [
            (b"", b"$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."),
            (b"a", b"$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"),
            (b"abc", b"$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"),
            (b"abcdefghijklmnopqrstuvwxyz",
             b"$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"),
            (b"~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
             b"$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"),
        ]
        for password, hashed in vectors:
            self.assertEqual(bcrypt_py.hashpw(password, hashed), hashed)
            self.assertTrue(bcrypt_py.checkpw(password, hashed))
            self.assertFalse(bcrypt_py.checkpw(password + b"!", hashed))

    @unittest.skipIf(native is None, "the bcrypt package is not installed")
    def test_identical_to_the_bcrypt_package(self):
        rng = random.Random(1)
        alphabet = "abcXYZ019 !$ąęłżźćńó€漢字🙂"
        for length in [0, 1, 7, 8, 20, 50, 71, 72] + [rng.randint(0, 72) for _ in range(8)]:
            password = "".join(rng.choice(alphabet) for _ in range(length)).encode()[:72]
            salt = native.gensalt(rounds=4)
            self.assertEqual(bcrypt_py.hashpw(password, salt), native.hashpw(password, salt))
            own = bcrypt_py.hashpw(password, bcrypt_py.gensalt(4))
            self.assertTrue(native.checkpw(password, own))

    def test_rejects_what_bcrypt_cannot_hash(self):
        salt = bcrypt_py.gensalt(4)
        with self.assertRaises(ValueError):
            bcrypt_py.hashpw(b"x" * 73, salt)
        with self.assertRaises(ValueError):
            bcrypt_py.hashpw(b"a\x00b", salt)
        with self.assertRaises(ValueError):
            bcrypt_py.hashpw(b"a", b"$2b$99$" + b"." * 22)
        self.assertFalse(bcrypt_py.checkpw(b"x" * 73, bcrypt_py.hashpw(b"x" * 72, salt)))


class PasswordModuleTest(unittest.TestCase):
    def setUp(self):
        reset_process_state()           # includes the fast bcrypt cost

    def test_hash_is_bcrypt_and_verifies(self):
        stored = passwords.hash_password("correct horse 42")
        self.assertTrue(stored.startswith("$2b$04$"))
        self.assertEqual(len(stored), 60)
        self.assertNotIn("correct horse", stored)
        self.assertTrue(passwords.verify_password("correct horse 42", stored))
        self.assertFalse(passwords.verify_password("correct horse 43", stored))

    def test_verify_never_raises(self):
        for stored in ("", "plaintext", "$2b$04$short", None, 42):
            self.assertFalse(passwords.verify_password("anything", stored))
        self.assertFalse(passwords.verify_password(None, passwords.hash_password("abcdefgh1")))

    def test_fallback_verifies_hashes_made_by_either_side(self):
        stored = passwords.hash_password("same password 1")
        with mock.patch.object(passwords, "_native", None):
            self.assertEqual(passwords.backend(), "builtin")
            self.assertTrue(passwords.verify_password("same password 1", stored))
            builtin = passwords.hash_password("same password 1")
        self.assertTrue(passwords.verify_password("same password 1", builtin))

    def test_policy(self):
        self.assertIsNone(passwords.problem("correct horse 42", "correct horse 42"))
        self.assertIn("at least", passwords.problem("short", "short"))
        self.assertIn("72 bytes", passwords.problem("ą" * 40, "ą" * 40))
        self.assertIn("too easy", passwords.problem("CHANGE_YOUR_PASSWORD", "CHANGE_YOUR_PASSWORD"))
        self.assertIn("too easy", passwords.problem("aaaaaaaaaa", "aaaaaaaaaa"))
        self.assertIn("do not match", passwords.problem("correct horse 42", "correct horse 43"))

    @unittest.skipIf(native is None, "the bcrypt package is not installed")
    def test_weak_hashes_are_upgraded_once_the_package_is_present(self):
        weak = bcrypt_py.hashpw(b"correct horse 42", bcrypt_py.gensalt(5)).decode()
        self.assertTrue(passwords.needs_rehash(weak))
        strong = native.hashpw(b"x", native.gensalt(10)).decode()
        self.assertFalse(passwords.needs_rehash(strong))
        with mock.patch.object(passwords, "_native", None):
            self.assertFalse(passwords.needs_rehash(weak))
            self.assertTrue(passwords.slow_to_verify(native.hashpw(b"x", native.gensalt(12)).decode()))

    def test_cost_calibration_stays_in_range(self):
        passwords._cost = None
        try:
            with mock.patch.object(passwords, "_native", None):
                cost = passwords.target_cost()
            self.assertTrue(passwords.FALLBACK_COSTS[0] <= cost <= passwords.FALLBACK_COSTS[1])
        finally:
            passwords._cost = 4


if __name__ == "__main__":
    unittest.main()
