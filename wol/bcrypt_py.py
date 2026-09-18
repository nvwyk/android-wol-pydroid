"""Pure-Python bcrypt ($2b$), used only when the bcrypt package is not installed.

Pydroid 3 cannot build bcrypt 4 or newer (it needs a Rust compiler), so without this
module a phone without the package could not store a bcrypt password hash at all. The
output is exactly what the bcrypt package produces for the same salt and cost;
tests/test_passwords.py checks that against the real package. It is roughly a hundred
times slower than the compiled version, which is why passwords.py gives it a lower cost.

Follows OpenBSD's bcrypt.c: EksBlowfish key setup, 64 encryptions of
"OrpheanBeholderScryDoubt", and bcrypt's own base64 alphabet.
"""
import base64
import hmac
import os

__all__ = ["hashpw", "checkpw", "gensalt"]

_MAGIC_WORDS = (0x4F727068, 0x65616E42, 0x65686F6C, 0x64657253, 0x63727944, 0x6F756274)
_STD_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCRYPT_B64 = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_TO_BCRYPT = bytes.maketrans(_STD_B64, _BCRYPT_B64)
_FROM_BCRYPT = bytes.maketrans(_BCRYPT_B64, _STD_B64)
_M = 0xFFFFFFFF
_initial = []       # [P, (S0, S1, S2, S3)] once computed


def _pi_words(count):
    """The first `count` 32-bit words of the fractional part of pi.

    Blowfish fills its P-array and S-boxes with exactly these digits, so they are
    computed here (Machin's formula on integers) instead of pasted in as 1042 constants.
    """
    guard = 64
    bits = 32 * count + guard
    unity = 1 << bits

    def arctan_inverse(x):
        total = term = unity // x
        square, divisor, sign = x * x, 1, -1
        while term:
            term //= square
            divisor += 2
            total += sign * (term // divisor)
            sign = -sign
        return total

    pi = 4 * (4 * arctan_inverse(5) - arctan_inverse(239))
    fraction = (pi - 3 * unity) >> guard
    return [(fraction >> (32 * (count - 1 - i))) & _M for i in range(count)]


def _initial_state():
    if not _initial:
        words = _pi_words(18 + 4 * 256)
        _initial.extend([words[:18], tuple(words[18 + 256 * i:18 + 256 * (i + 1)]
                                           for i in range(4))])
    p, s = _initial
    return list(p), [list(box) for box in s]


def _stream_words(data, count):
    """`count` big-endian words read cyclically from `data`, like stream2word() in C."""
    out, j = [], 0
    for _ in range(count):
        word = 0
        for _ in range(4):
            word = (word << 8) | data[j]
            j = (j + 1) % len(data)
        out.append(word)
    return out


def _encipher(P, S0, S1, S2, S3, l, r):
    """One Blowfish block. Reads P live because key setup rewrites it between blocks."""
    l ^= P[0]
    for n in range(1, 17, 2):
        r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & _M ^ P[n]
        l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & _M ^ P[n + 1]
    return r ^ P[17], l


def _expand_state(P, S, salt_words, key_words):
    """ExpandKey with a salt: the one-off first step of EksBlowfishSetup."""
    S0, S1, S2, S3 = S
    for i in range(18):
        P[i] ^= key_words[i]
    l = r = 0
    j = 0
    for i in range(0, 18, 2):
        l ^= salt_words[j]
        r ^= salt_words[j + 1]
        j = (j + 2) % 4
        l, r = _encipher(P, S0, S1, S2, S3, l, r)
        P[i], P[i + 1] = l, r
    for box in S:
        for i in range(0, 256, 2):
            l ^= salt_words[j]
            r ^= salt_words[j + 1]
            j = (j + 2) % 4
            l, r = _encipher(P, S0, S1, S2, S3, l, r)
            box[i], box[i + 1] = l, r


def _expand0(P, S, key_words):
    """ExpandKey without a salt. This runs 2**(cost + 1) times, so it is written out flat.

    While the S-boxes are refilled the P-array stays fixed, so its 18 words become
    locals and the 16 rounds are unrolled: the fastest shape plain CPython offers.
    """
    S0, S1, S2, S3 = S
    for i in range(18):
        P[i] ^= key_words[i]
    l = r = 0
    for i in range(0, 18, 2):
        l, r = _encipher(P, S0, S1, S2, S3, l, r)
        P[i], P[i + 1] = l, r
    p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15, p16, p17 = P
    M = _M
    for box in S:
        for i in range(0, 256, 2):
            l ^= p0
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p1
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p2
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p3
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p4
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p5
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p6
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p7
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p8
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p9
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p10
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p11
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p12
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p13
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p14
            r ^= (((S0[l >> 24] + S1[l >> 16 & 255]) ^ S2[l >> 8 & 255]) + S3[l & 255]) & M ^ p15
            l ^= (((S0[r >> 24] + S1[r >> 16 & 255]) ^ S2[r >> 8 & 255]) + S3[r & 255]) & M ^ p16
            l, r = r ^ p17, l
            box[i], box[i + 1] = l, r


def _raw_hash(password, salt, cost):
    """The 23 hash bytes bcrypt encodes for this password (<= 72 bytes), salt and cost."""
    key = password[:72] + b"\x00"           # $2b$ keys include the C string terminator
    key_words = _stream_words(key, 18)
    salt_words = _stream_words(salt, 18)
    P, S = _initial_state()
    _expand_state(P, S, salt_words, key_words)
    for _ in range(1 << cost):
        _expand0(P, S, key_words)
        _expand0(P, S, salt_words)
    S0, S1, S2, S3 = S
    words = list(_MAGIC_WORDS)
    for block in range(0, 6, 2):
        l, r = words[block], words[block + 1]
        for _ in range(64):
            l, r = _encipher(P, S0, S1, S2, S3, l, r)
        words[block], words[block + 1] = l, r
    return b"".join(word.to_bytes(4, "big") for word in words)[:23]


def _encode(data):
    return base64.b64encode(data).rstrip(b"=").translate(_TO_BCRYPT)


def _decode_salt(text):
    salt = base64.b64decode(text.translate(_FROM_BCRYPT) + b"==")
    if len(salt) != 16:
        raise ValueError("Invalid salt")
    return salt


def gensalt(rounds=12, prefix=b"2b"):
    if prefix not in (b"2a", b"2b"):
        raise ValueError("Supported prefixes are b'2a' or b'2b'")
    if not 4 <= rounds <= 31:
        raise ValueError("Invalid rounds")
    return b"$" + prefix + b"$%02d$" % rounds + _encode(os.urandom(16))


def _parse(setting):
    """(prefix, cost, salt text) from a salt or a full hash, else ValueError."""
    if not isinstance(setting, bytes):
        raise TypeError("Salt must be bytes")
    parts = setting.split(b"$")
    if (len(parts) != 4 or parts[0] or parts[1] not in (b"2a", b"2b", b"2y")
            or len(parts[2]) != 2 or not parts[2].isdigit() or len(parts[3]) < 22):
        raise ValueError("Invalid salt")
    cost = int(parts[2])
    if not 4 <= cost <= 31:
        raise ValueError("Invalid salt")
    salt_text = parts[3][:22]
    if salt_text.translate(None, _BCRYPT_B64):
        raise ValueError("Invalid salt")
    return parts[1], cost, salt_text


def hashpw(password, salt):
    """bcrypt.hashpw(): the full 60-byte hash of `password` under `salt` (or a full hash)."""
    if not isinstance(password, bytes):
        raise TypeError("Unicode-objects must be encoded before hashing")
    if b"\x00" in password:
        raise ValueError("password may not contain NUL bytes")
    if len(password) > 72:
        raise ValueError("password cannot be longer than 72 bytes")
    prefix, cost, salt_text = _parse(salt)
    digest = _raw_hash(password, _decode_salt(salt_text), cost)
    return b"$" + prefix + b"$%02d$" % cost + salt_text + _encode(digest)


def checkpw(password, hashed_password):
    """bcrypt.checkpw(): True when `password` produces `hashed_password`. Constant time."""
    if not isinstance(password, bytes) or not isinstance(hashed_password, bytes):
        raise TypeError("Unicode-objects must be encoded before checking")
    if len(hashed_password) != 60:
        raise ValueError("Invalid hashed_password")
    if b"\x00" in password or len(password) > 72:
        return False
    return hmac.compare_digest(hashpw(password, hashed_password), hashed_password)
