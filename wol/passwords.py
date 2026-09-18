"""Password hashes. Always bcrypt, never plaintext, never a fast hash.

The bcrypt package (compiled) is used when it is installed. Pydroid 3 often cannot
install it: bcrypt 4 and newer need a Rust compiler to build, which Pydroid does not
ship. bcrypt_py then provides the same algorithm in plain Python. Both write standard
$2b$ hashes that either one can verify.

The cost is picked once per run: the highest cost in the allowed range that still hashes
in about a second on this device. The plain-Python version is roughly a hundred times
slower, so its range is lower. A hash made by it is upgraded to the package's stronger
cost at the next sign-in after the package is installed.
"""
import threading
import time

from . import bcrypt_py

try:
    import bcrypt as _native
    _native.hashpw
except Exception:           # not installed, or a broken install; either way use the fallback
    _native = None

MIN_LENGTH = 8
MAX_BYTES = 72              # bcrypt only reads 72 bytes; longer passwords are refused, not cut
NATIVE_COSTS = (10, 12)
FALLBACK_COSTS = (5, 8)
TIME_BUDGET = 1.0           # seconds one hash may take on this device

# Too predictable to protect anything, the old default placeholder included.
TRIVIAL = {"password", "password1", "12345678", "123456789", "1234567890", "87654321",
           "qwertyuiop", "qwertyui", "11111111", "00000000", "changeme", "adminadmin",
           "change_your_password", "letmein1", "iloveyou"}

_cost = None
_cost_lock = threading.Lock()


def backend():
    return "native" if _native is not None else "builtin"


def _module():
    return _native if _native is not None else bcrypt_py


def cost_of(stored):
    """The cost factor written in a bcrypt hash, or None if it is not one."""
    parts = str(stored).split("$")
    if len(parts) == 4 and parts[1] in ("2a", "2b", "2y") and parts[2].isdigit():
        return int(parts[2])
    return None


def target_cost():
    """The cost used for new hashes on this device, measured on first use."""
    global _cost
    with _cost_lock:
        if _cost is None:
            low, high = NATIVE_COSTS if _native is not None else FALLBACK_COSTS
            module = _module()
            started = time.perf_counter()
            module.hashpw(b"calibration", module.gensalt(low))
            elapsed = max(time.perf_counter() - started, 1e-4)
            cost = low
            while cost < high and elapsed * 2 <= TIME_BUDGET:
                cost += 1
                elapsed *= 2
            _cost = cost
        return _cost


def hash_password(password):
    """A new bcrypt password hash (str). Validate the password with problem() first."""
    module = _module()
    return module.hashpw(password.encode("utf-8"), module.gensalt(target_cost())).decode("ascii")


def verify_password(password, stored):
    """True when `password` matches the stored hash. False for anything malformed.

    The comparison is the bcrypt implementation's own constant-time check.
    """
    try:
        candidate = password.encode("utf-8")
        hashed = stored.encode("ascii")
    except (AttributeError, UnicodeError):
        return False
    if len(candidate) > MAX_BYTES or b"\x00" in candidate or cost_of(stored) is None:
        return False
    try:
        return bool(_module().checkpw(candidate, hashed))
    except (TypeError, ValueError):
        return False


def needs_rehash(stored):
    """True when the stored hash is weaker than what this device can now afford."""
    cost = cost_of(stored)
    return _native is not None and (cost is None or cost < NATIVE_COSTS[0])


def slow_to_verify(stored):
    """True when the hash was made with the bcrypt package, which is missing now: the
    plain-Python check of such a hash can take minutes on a phone."""
    cost = cost_of(stored)
    return _native is None and cost is not None and cost > FALLBACK_COSTS[1]


def problem(password, confirmation):
    """Why a new password cannot be used, or None when it is fine."""
    if len(password) < MIN_LENGTH:
        return "Use at least %d characters." % MIN_LENGTH
    if len(password.encode("utf-8")) > MAX_BYTES:
        return ("Use at most %d bytes. That is %d plain letters, fewer with accents "
                "or emoji." % (MAX_BYTES, MAX_BYTES))
    if "\x00" in password or not password.strip():
        return "Use visible characters."
    if password.lower() in TRIVIAL or len(set(password)) < 3:
        return "That password is too easy to guess. Choose another."
    if password != confirmation:
        return "The two passwords do not match."
    return None


def describe():
    """How new hashes are made, for the admin Security page."""
    cost = _cost
    if _native is not None:
        return "bcrypt package%s" % (", cost %d" % cost if cost else "")
    return "Built-in bcrypt%s (install the bcrypt package for a stronger cost)" % (
        ", cost %d" % cost if cost else "")
