from emmett_crypto.symmetric import encrypt_b64, encrypt_hex, decrypt_b64, decrypt_hex

text = b"plain text"
key = "some key"


def test_b64():
    ct = encrypt_b64(text, key)
    assert decrypt_b64(ct, key) == text


def test_hex():
    ct = encrypt_hex(text, key)
    assert decrypt_hex(ct, key) == text
