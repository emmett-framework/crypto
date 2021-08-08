import codecs

from enum import Enum

from . import _kdf


class PBKDF2_HMAC(Enum):
    sha1 = _kdf.pbkdf2_sha1
    sha256 = _kdf.pbkdf2_sha256
    sha384 = _kdf.pbkdf2_sha384
    sha512 = _kdf.pbkdf2_sha512


def pbkdf2_bin(
    data: bytes,
    salt: bytes,
    iterations: int = 10000,
    keylen: int = 32,
    hash_algorithm: PBKDF2_HMAC = PBKDF2_HMAC.sha256
) -> bytes:
    return hash_algorithm.value(
        data,
        salt,
        iterations,
        keylen
    )


def pbkdf2_hex(
    data: str,
    salt: str,
    iterations: int = 10000,
    keylen: int = 32,
    hash_algorithm: PBKDF2_HMAC = PBKDF2_HMAC.sha256
) -> str:
    return codecs.encode(
        pbkdf2_bin(
            data=data.encode("utf8"),
            salt=salt.encode("utf8"),
            iterations=iterations,
            keylen=keylen,
            hash_algorithm=hash_algorithm
        ),
        "hex_codec"
    ).decode("utf8")
