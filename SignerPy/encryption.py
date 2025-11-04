from base64 import b64decode, b64encode
from urllib.parse import parse_qsl, urlencode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def enc(r):
    s = urlencode(r, doseq=True, quote_via=lambda s, *_: s)
    key = "webapp1.0+202106".encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, key)
    ct_bytes = cipher.encrypt(pad(s.encode("utf-8"), AES.block_size))
    return b64encode(ct_bytes).decode("utf-8")


def dec(s):
    key = "webapp1.0+202106".encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, key)
    ct = b64decode(s)
    s = unpad(cipher.decrypt(ct), AES.block_size)
    return dict(parse_qsl(s.decode("utf-8"), keep_blank_values=True))