from binascii import unhexlify
from io import StringIO


def pkcs7_pad(data, plen: int = 16):
    l = len(data)
    output = StringIO()
    val = plen - (l % plen)
    for _ in range(val):
        output.write('%02x' % val)
    return data + unhexlify(output.getvalue())


def pkcs7_unpad(data, blks: int = 1):
    return data[:-data[-blks]]
