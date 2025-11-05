import time, json
from urllib.parse import urlencode, parse_qs
from random import randint
from struct import unpack
from base64 import b64encode
from hashlib import md5
from Crypto.Cipher.AES import new, MODE_CBC, block_size
from .sm3 import SM3
from .simon import simon_enc
from .protobuf import ProtoBuf

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

class Argus:
    def encrypt_enc_pb(data, l):
        data = list(data)
        xor_array = data[:8]
        
        for i in range(8, l):
            data[i] ^= xor_array[i % 8]

        return bytes(data[::-1])
    
    @staticmethod
    def get_bodyhash(stub: str or None = None) -> bytes:
        return (
            SM3().sm3_hash(bytes(16))[0:6] if stub == None or len(stub) == 0 else SM3().sm3_hash(bytes.fromhex(stub))[0:6])

    @staticmethod
    def get_queryhash(query: str) -> bytes:
        return (
            SM3().sm3_hash(bytes(16))[0:6] if query == None or len(query) == 0 else SM3().sm3_hash(query.encode())[0:6])

    @staticmethod
    def encrypt(xargus_bean: dict):
        protobuf = pkcs7_pad(bytes.fromhex(ProtoBuf(xargus_bean).toBuf().hex()), block_size)
        new_len = len(protobuf)
        sign_key = b"\xc0/%\x0f\x86\xccO\x19\x8dW\x069\x8d)*\x8bt\x16\x9a\xbaa\xaf\xfe|\xba\x02\xe4\xa3\xb5\x19\x81c"
        sm3_output = b'\xfcx\xe0\xa9ez\x0ct\x8c\xe5\x15Y\x90<\xcf\x03Q\x0eQ\xd3\xcf\xf22\xd7\x13C\xe8\x8a2\x1cS\x04'

        key = sm3_output[:32]
        key_list = []
        enc_pb = bytearray(new_len)
        
        for _ in range(2): 
            key_list = key_list + list(unpack("<QQ", key[_ * 16 : _ * 16 + 16]))
        
        for _ in range(int(new_len / 16)):
            pt = list(unpack("<QQ", protobuf[_ * 16 : _ * 16 + 16]))
            ct = simon_enc(pt, key_list)
            enc_pb[_ * 16 : _ * 16 + 8] = ct[0].to_bytes(8, byteorder="little")
            enc_pb[_ * 16 + 8 : _ * 16 + 16] = ct[1].to_bytes(8, byteorder="little")

        b_buffer = Argus.encrypt_enc_pb((b"\xf2\xf7\xfc\xff\xf2\xf7\xfc\xff" + enc_pb), new_len + 8)
        b_buffer = b'\xa6n\xad\x9fw\x01\xd0\x0c\x18' + b_buffer + b'ao'
        
        cipher = new(md5(sign_key[:16]).digest(), MODE_CBC, md5(sign_key[16:]).digest())

        return b64encode(b"\xf2\x81" + cipher.encrypt(pkcs7_pad(b_buffer, block_size))).decode()
    
    @staticmethod
    def get_sign(queryhash: None or str = None,
                    data: None or str = None,
                    timestamp: int = int(time.time()),
                    aid: int = 1233,
                    license_id: int = 1611921764,
                    platform: int = 0,
                    sec_device_id: str = "",
                    sdk_version: str = "v04.04.05-ov-android",
                    sdk_version_int: int = 134744640) -> dict:
        
        params_dict = parse_qs(queryhash)

        version_key = None
        for key in ("app_version", "ab_version", "build_number", "version_name"):
            if key in params_dict:
                version_key = key
                break

        if version_key:
            value = params_dict[version_key]
            if isinstance(value, (list, tuple)):
                value = value[0]
            p = str(value).split('.')
        else:
            p = ['0', '0', '0']

        params_dict['app_version']=p
        app_version_hash = bytes.fromhex('{:x}{:x}{:x}00'.format(int(p[2]) * 4, int(p[1]) * 16, int(p[0]) * 4).zfill(8))
        app_version_constant = (int.from_bytes(app_version_hash, byteorder='big') << 1)
        osVersion = params_dict['os_version'][0]
        osVersion = osVersion.split(".") 
        for _ in range(3 - len(osVersion)):
            osVersion.append(0)

        return Argus.encrypt({
            1: 0x20200929 << 1,
            2: 2,
            3: randint(0, 0x7FFFFFFF),
            4: str(aid),
            5: params_dict['device_id'][0],
            6: str(license_id),
            7: params_dict['app_version'][0],
            8: sdk_version,
            9: sdk_version_int,
            10: bytes(8),
            12: (timestamp << 1),
            13: Argus.get_bodyhash(data),
            14: Argus.get_queryhash(queryhash),
            16: sec_device_id,
            20: "none",
            21: 738,
            25: 2
        })