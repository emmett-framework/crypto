from emmett_crypto.ciphers import AESModes, aes_encrypt, aes_decrypt

text = b"plain text"


def test_aes128_ctr():
    key = b"a" * 16
    iv = b"b" * 16

    ct = aes_encrypt(text, key, iv, AESModes.CTR128)
    assert ct == b'i%\xd4\xcd\x1ew6R\xa9\xf3'
    assert aes_decrypt(ct, key, iv, AESModes.CTR128) == text


def test_aes256_ctr():
    key = b"a" * 32
    iv = b"b" * 16

    ct = aes_encrypt(text, key, iv, AESModes.CTR128)
    assert ct == b'\xba\x18&\xe2\x81\x1b\x85Xr\xbb'
    assert aes_decrypt(ct, key, iv, AESModes.CTR128) == text


def test_aes128_cfb8():
    key = b"a" * 16
    iv = b"b" * 16

    ct = aes_encrypt(text, key, iv, AESModes.CFB8)
    assert ct == b'i\x9d\xe6\xc1\xefTC\xd0\xb1\x8e'
    assert aes_decrypt(ct, key, iv, AESModes.CFB8) == text


def test_aes256_cfb8():
    key = b"a" * 32
    iv = b"b" * 16

    ct = aes_encrypt(text, key, iv, AESModes.CFB8)
    assert ct == b'\xba\xe1"\x85\x0f\t\x84\x91\xb2E'
    assert aes_decrypt(ct, key, iv, AESModes.CFB8) == text


def test_aes128_cfb8():
    key = b"a" * 16
    iv = b"b" * 16

    ct = aes_encrypt(text, key, iv, AESModes.CFB128)
    assert ct == b'i%\xd4\xcd\x1ew6R\xa9\xf3'
    assert aes_decrypt(ct, key, iv, AESModes.CFB128) == text


def test_aes256_cfb8():
    key = b"a" * 32
    iv = b"b" * 16

    ct = aes_encrypt(text, key, iv, AESModes.CFB128)
    assert ct == b'\xba\x18&\xe2\x81\x1b\x85Xr\xbb'
    assert aes_decrypt(ct, key, iv, AESModes.CFB128) == text
