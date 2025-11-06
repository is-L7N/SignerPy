from time import time
from hashlib import md5
import hashlib
from random import choice
from urllib.parse import urlencode


def _normalize(value):
    if isinstance(value, dict):
        return urlencode(value)
    elif value is None:
        return ""
    else:
        return str(value)

class Gorgon:
    def __init__(self, params=None, unix=None, payload=None, cookie=None, version: int or None=None):
        self.params = _normalize(params)
        self.payload = _normalize(payload)
        self.cookies = _normalize(cookie)
        self.unix = int(unix) if unix is not None else int(time())
        self.version = version 

    def get_value(self):
        if self.version == 8404:
            return GorgonV1(self.params, self.unix, self.payload, self.cookies).get_value()
        elif self.version == 8402:
            return GorgonV2(self.params, self.unix, self.payload, self.cookies).get_value()
        elif self.version == 4404 or self.version ==None:
            return GorgonV3(self.params, self.unix, self.payload, self.cookies).get_value()
        else:
            raise ValueError("Unsupported Gorgon version (choose 8404, 8402, or 4404)")


class GorgonV1:
    def __init__(self, params, unix=None, payload=None, cookie=None):
        self.params = params
        self.payload = payload
        self.cookie = cookie
        self.unix = int(unix) if unix is not None else int(time())

    def hash(self, data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()

    def get_value(self):
        gorgon = []
        url_md5 = self.hash(self.params)
        gorgon += [int(url_md5[i * 2:i * 2 + 2], 16) for i in range(4)]

        if self.payload:
            data_md5 = self.hash(self.payload)
            gorgon += [int(data_md5[i * 2:i * 2 + 2], 16) for i in range(4)]
        else:
            gorgon += [0x0] * 4

        if self.cookie:
            cookie_md5 = self.hash(self.cookie)
            gorgon += [int(cookie_md5[i * 2:i * 2 + 2], 16) for i in range(4)]
        else:
            gorgon += [0x0] * 4

        gorgon += [0x1, 0x1, 0x2, 0x4]
        Khronos = hex(int(self.unix))[2:].rjust(8, '0')
        gorgon += [int(Khronos[i * 2:i * 2 + 2], 16) for i in range(4)]
        xg = XG(gorgon)
        return {
            "x-ss-req-ticket": str(int(self.unix * 1000)),
            "x-khronos": str(int(self.unix)),
            "x-gorgon": xg.main()
        }


class XG:
    def __init__(self, debug):
        self.debug = debug
        self.length = 0x14
        self.hex_CE0 = [0x05, 0x00, 0x50, choice(range(0, 0xFF)), 0x47, 0x1e, 0x00, choice(range(0, 0xFF)) & 0xf0]

    def hex_string(self, num):
        return hex(num)[2:].rjust(2, '0')

    def main(self):
        result = ''
        for item in self.debug:
            result += self.hex_string(item)
        return '8404{}{}{}{}{}'.format(
            self.hex_string(self.hex_CE0[7]),
            self.hex_string(self.hex_CE0[3]),
            self.hex_string(self.hex_CE0[1]),
            self.hex_string(self.hex_CE0[6]),
            result
        )


class GorgonV2:
    def __init__(self, params, unix=None, payload=None, cookie=None):
        self.params = params
        self.data = payload
        self.cookies = cookie
        self.unix = int(unix) if unix is not None else int(time())

    def _to_bytes(self, v):
        if v is None:
            return b""
        if isinstance(v, bytes):
            return v
        return str(v).encode("utf-8")

    def _md5_hex(self, b: bytes) -> str:
        return md5(b).hexdigest()

    def _build_param_list(self) -> list:
        param_list = []
        params_md5 = self._md5_hex(self._to_bytes(self.params))
        for i in range(4):
            param_list.append(int(params_md5[i * 2:i * 2 + 2], 16))
        if self.data:
            data_md5 = self._md5_hex(self._to_bytes(self.data))
            for i in range(4):
                param_list.append(int(data_md5[i * 2:i * 2 + 2], 16))
        else:
            param_list += [0x0] * 4
        if self.cookies:
            cookie_md5 = self._md5_hex(self._to_bytes(self.cookies))
            for i in range(4):
                param_list.append(int(cookie_md5[i * 2:i * 2 + 2], 16))
        else:
            param_list += [0x0] * 4
        param_list += [0x0, 0x6, 0xB, 0x1C]
        H = int(self.unix) & 0xFFFFFFFF
        param_list += [(H >> 24) & 0xFF, (H >> 16) & 0xFF, (H >> 8) & 0xFF, H & 0xFF]
        return param_list

    def rbit(self, num: int) -> int:
        s = bin(num)[2:].rjust(8, "0")[::-1]
        return int(s, 2)

    def hex_string(self, num: int) -> str:
        return hex(num)[2:].rjust(2, "0")

    def reverse(self, num: int) -> int:
        tmp = self.hex_string(num)
        return int(tmp[1:] + tmp[:1], 16)

    def encrypt(self):
        unix = int(self.unix)
        length = 0x14
        key = [0xDF, 0x77, 0xB9, 0x40, 0xB9, 0x9B, 0x84, 0x83, 0xD1, 0xB9,
               0xCB, 0xD1, 0xF7, 0xC2, 0xB9, 0x85, 0xC3, 0xD0, 0xFB, 0xC3]
        param_list = self._build_param_list()
        eor_result_list = [A ^ B for A, B in zip(param_list, key)]
        for i in range(length):
            C = self.reverse(eor_result_list[i])
            D = eor_result_list[(i + 1) % length]
            E = C ^ D
            F = self.rbit(E)
            H = ((F ^ 0xFFFFFFFF) ^ length) & 0xFF
            eor_result_list[i] = H
        result = "".join(self.hex_string(p) for p in eor_result_list)
        return {
            "x-ss-req-ticket": str(int(unix * 1000)),
            "x-khronos": str(int(unix)),
            "x-gorgon": f"840280416000{result}",
        }

    def get_value(self):
        return self.encrypt()


class GorgonV3(GorgonV2):
    def encrypt(self):
        result = super().encrypt()
        result["x-gorgon"] = result["x-gorgon"].replace("840280416000", "0404b0d30000")
        return result
                   