from emmett_crypto.kdf import pbkdf2_bin


def test_pbkdf2():
    key = pbkdf2_bin(
        b"some password",
        b"a" * 16,
        32
    )
    assert key == b'oQ\xbd-\xdb\x04\x85VT\x00\xc4\xcco\x8d\xc4~\xd3~(\x9e\xaa\xb8\x95\xacQ\xc4c\xa2\xbc1\x83*'
