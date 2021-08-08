import hmac
import os

from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import hexlify, unhexlify
from typing import Tuple, Union

from . import _ciphers, _kdf


def encrypt(data: Union[bytes, str], key: str) -> Tuple[bytes, bytes, bytes]:
    if isinstance(data, str):
        data = data.encode("utf8")
    klen, ivlen, salt = 256 // 8, 128 // 8, os.urandom(32)
    dkey = _kdf.pbkdf2_sha256(
        key.encode("utf8"),
        salt,
        1000,
        klen * 2 + ivlen
    )
    k1 = dkey[:klen]
    k2 = dkey[klen:(klen * 2)]
    nonce = dkey[(klen * 2):(klen * 2) + ivlen]
    cipher = _ciphers.aes256_ctr128(data, k1, nonce)
    signature = hmac.digest(k2, cipher, "sha256")
    return cipher, salt, signature


def decrypt(data: bytes, salt: bytes, signature: bytes, key: str) -> bytes:
    klen, ivlen = 256 // 8, 128 // 8
    dkey = _kdf.pbkdf2_sha256(
        key.encode("utf8"),
        salt,
        1000,
        klen * 2 + ivlen
    )
    k1 = dkey[:klen]
    k2 = dkey[klen:(klen * 2)]
    nonce = dkey[(klen * 2):(klen * 2) + ivlen]
    if not hmac.compare_digest(signature, hmac.digest(k2, data, "sha256")):
        raise ValueError("Signature verification failed")
    return _ciphers.aes256_ctr128(data, k1, nonce)


def encrypt_hex(data: Union[bytes, str], key: str, jchar: str = ":") -> str:
    cipher, salt, signature = encrypt(data, key)
    return jchar.join(
        hexlify(v).decode("utf8") for v in [salt, signature, cipher]
    )


def decrypt_hex(data: Union[bytes, str], key: str, jchar: str = ":") -> bytes:
    try:
        salt, signature, cipher = data.split(jchar)
    except ValueError:
        raise ValueError("Invalid data input")
    return decrypt(unhexlify(cipher), unhexlify(salt), unhexlify(signature), key)


def encrypt_b64(data: Union[bytes, str], key: str, jchar: str = ":") -> str:
    cipher, salt, signature = encrypt(data, key)
    return jchar.join(
        urlsafe_b64encode(v).decode("utf8") for v in [salt, signature, cipher]
    )


def decrypt_b64(data: Union[bytes, str], key: str, jchar: str = ":") -> bytes:
    try:
        salt, signature, cipher = data.split(jchar)
    except ValueError:
        raise ValueError("Invalid data input")
    return decrypt(
        urlsafe_b64decode(cipher),
        urlsafe_b64decode(salt),
        urlsafe_b64decode(signature),
        key
    )
