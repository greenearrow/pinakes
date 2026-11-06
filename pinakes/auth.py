"""Passwords (scrypt) and second factors (TOTP, RFC 6238), standard library only."""

import base64
import hashlib
import hmac
import os
import struct
import time

_N, _R, _P = 2 ** 15, 8, 1      # about 32 MB and a few tenths of a second per check


def hash_password(password):
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (_N, _R, _P, base64.b64encode(salt).decode(), base64.b64encode(h).decode())


def check_password(password, stored):
    try:
        alg, n, r, p, salt, h = stored.split("$")
        if alg != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(got, base64.b64decode(h))
    except (ValueError, AttributeError):
        return False


# a hash to check against when the name is unknown, so both cases take the same time
DUMMY_HASH = hash_password("not a real password")


def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def totp(secret, at=None, step=30, digits=6):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return "%0*d" % (digits, code)


def check_totp(secret, code, window=1, at=None):
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    now = time.time() if at is None else at
    return any(hmac.compare_digest(totp(secret, now + 30 * w), code) for w in range(-window, window + 1))


def otpauth_uri(secret, account, issuer="pinakes"):
    from urllib.parse import quote
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s" % (quote(issuer), quote(account), secret, quote(issuer))
