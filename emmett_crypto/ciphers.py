from enum import Enum

from . import _crypto

AES_BLOCK_SIZE = 128 // 8


class AESModes(Enum):
    CFB8 = {
        128 // 8: (_crypto.aes128_cfb8_encrypt, _crypto.aes128_cfb8_decrypt),
        256 // 8: (_crypto.aes256_cfb8_encrypt, _crypto.aes256_cfb8_decrypt)
    }
    CFB128 = {
        128 // 8: (_crypto.aes128_cfb128_encrypt, _crypto.aes128_cfb128_decrypt),
        256 // 8: (_crypto.aes256_cfb128_encrypt, _crypto.aes256_cfb128_decrypt)
    }
    CTR128 = {
        128 // 8: (_crypto.aes128_ctr128, _crypto.aes128_ctr128),
        256 // 8: (_crypto.aes256_ctr128, _crypto.aes256_ctr128)
    }


def aes_encrypt(
    data: bytes,
    key: bytes,
    nonce: bytes,
    mode: AESModes = AESModes.CTR128
) -> bytes:
    try:
        method, _ = mode.value[len(key)]
    except KeyError:
        raise ValueError(f"key must be 16 or 32 bytes long")
    assert len(nonce) == AES_BLOCK_SIZE, f"nonce must be {AES_BLOCK_SIZE} bytes long"
    return method(
        data,
        key,
        nonce
    )


def aes_decrypt(
    data: bytes,
    key: bytes,
    nonce: bytes,
    mode: AESModes = AESModes.CTR128
) -> bytes:
    try:
        _, method = mode.value[len(key)]
    except KeyError:
        raise ValueError(f"key must be 16 or 32 bytes long")
    assert len(nonce) == AES_BLOCK_SIZE, f"nonce must be {AES_BLOCK_SIZE} bytes long"
    return method(
        data,
        key,
        nonce
    )
