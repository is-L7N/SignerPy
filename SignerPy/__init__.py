import requests, random, time, secrets, binascii, os, uuid,user_agent,re,string,json
from urllib.parse import urlencode
from random              import randint
from time                import time
from struct              import unpack
from base64              import b64encode
from hashlib             import md5
from urllib.parse        import parse_qs
from Crypto.Cipher.AES   import new, MODE_CBC, block_size


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)
class SM3:
    def __init__(self) -> None:
        self.IV = [1937774191, 1226093241, 388252375, 3666478592, 2842636476, 372324522, 3817729613, 2969243214]
        self.TJ = [2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042]
    
    def __rotate_left(self, a: int, k: int) -> int:
        k = k % 32

        return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))

    def __FFJ(self, X: int, Y: int, Z: int, j: int) -> int:

        if 0 <= j and j < 16:
            ret = X ^ Y ^ Z
        elif 16 <= j and j < 64:
            ret = (X & Y) | (X & Z) | (Y & Z)

        return ret

    def __GGJ(self, X: int, Y: int, Z: int, j: int) -> int:

        if 0 <= j and j < 16:
            ret = X ^ Y ^ Z
        elif 16 <= j and j < 64:
            ret = (X & Y) | ((~X) & Z)

        return ret

    def __P_0(self, X: int) -> int:
        return X ^ (self.__rotate_left(X, 9)) ^ (self.__rotate_left(X, 17))

    def __P_1(self, X: int) -> int:
        Z = X ^ (self.__rotate_left(X, 15)) ^ (self.__rotate_left(X, 23))

        return Z

    def __CF(self, V_i: list, B_i: bytearray) -> list:

        W = []
        for i in range(16):
            weight = 0x1000000
            data = 0
            for k in range(i * 4, (i + 1) * 4):
                data = data + B_i[k] * weight
                weight = int(weight / 0x100)
            W.append(data)

        for j in range(16, 68):
            W.append(0)
            W[j] = (
                self.__P_1(W[j - 16] ^ W[j - 9] ^ (self.__rotate_left(W[j - 3], 15)))
                ^ (self.__rotate_left(W[j - 13], 7))
                ^ W[j - 6]
            )

        W_1 = []
        for j in range(0, 64):
            W_1.append(0)
            W_1[j] = W[j] ^ W[j + 4]

        A, B, C, D, E, F, G, H = V_i

        for j in range(0, 64):

            SS1 = self.__rotate_left(
                ((self.__rotate_left(A, 12)) + E + (self.__rotate_left(self.TJ[j], j)))
                & 0xFFFFFFFF,
                7,
            )

            SS2 = SS1 ^ (self.__rotate_left(A, 12))
            TT1 = (self.__FFJ(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
            TT2 = (self.__GGJ(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = self.__rotate_left(B, 9)
            B = A
            A = TT1
            H = G
            G = self.__rotate_left(F, 19)
            F = E
            E = self.__P_0(TT2)

        return [
            A & 0xFFFFFFFF ^ V_i[0],
            B & 0xFFFFFFFF ^ V_i[1],
            C & 0xFFFFFFFF ^ V_i[2],
            D & 0xFFFFFFFF ^ V_i[3],
            E & 0xFFFFFFFF ^ V_i[4],
            F & 0xFFFFFFFF ^ V_i[5],
            G & 0xFFFFFFFF ^ V_i[6],
            H & 0xFFFFFFFF ^ V_i[7],
        ]

    def sm3_hash(self, msg: bytes) -> bytes:
        msg = bytearray(msg)
        len1 = len(msg)
        reserve1 = len1 % 64
        msg.append(0x80)
        reserve1 = reserve1 + 1
        # 56-64, add 64 byte
        range_end = 56
        if reserve1 > range_end:
            range_end += 64

        for i in range(reserve1, range_end):
            msg.append(0x00)

        bit_length = (len1) * 8
        bit_length_str = [bit_length % 0x100]
        for i in range(7):
            bit_length = int(bit_length / 0x100)
            bit_length_str.append(bit_length % 0x100)
        for i in range(8):
            msg.append(bit_length_str[7 - i])

        group_count = round(len(msg) / 64)

        B = []
        for i in range(0, group_count):
            B.append(msg[i * 64 : (i + 1) * 64])

        V = []
        V.append(self.IV)
        for i in range(0, group_count):
            V.append(self.__CF(V[i], B[i]))

        y = V[i + 1]
        res = b""

        for i in y:
            res += int(i).to_bytes(4, "big")

        return res
from ctypes import c_ulonglong

def get_bit(val, pos):
    return 1 if val & (1 << pos) else 0

def rotate_left(v, n):
    r = (v << n) | (v >> (64 - n))
    return r & 0xffffffffffffffff

def rotate_right(v, n):
    r = (v << (64 - n)) | (v >> n) 
    return r & 0xffffffffffffffff

def key_expansion(key):
    tmp = 0
    for i in range(4, 72):
        tmp = rotate_right(key[i-1], 3)
        tmp = tmp ^ key[i-3]
        tmp = tmp ^ rotate_right(tmp, 1)
        key[i] = c_ulonglong(~key[i-4]).value ^ tmp ^ get_bit(0x3DC94C3A046D678B, (i - 4) % 62) ^ 3
    return key

def simon_dec(ct, k, c=0):
    tmp = 0
    f = 0
    key = [0] * 72

    key[0] = k[0]
    key[1] = k[1]
    key[2] = k[2]
    key[3] = k[3]

    key = key_expansion(key)

    x_i = ct[0]
    x_i1 = ct[1]

    for i in range(72-1, -1, -1):
        tmp = x_i
        f = rotate_left(x_i, 1) if c == 1 else rotate_left(x_i, 1) & rotate_left(x_i, 8)
        x_i = x_i1 ^ f ^ rotate_left(x_i, 2) ^ key[i]
        x_i1 = tmp

    pt = [x_i, x_i1]
    return pt

def simon_enc(pt, k, c=0):
    tmp = 0
    f = 0
    key = [0] * 72
    key[0] = k[0]
    key[1] = k[1]
    key[2] = k[2]
    key[3] = k[3]

    key = key_expansion(key)

    x_i = pt[0]
    x_i1 = pt[1]

    for i in range(72):
        tmp = x_i1
        f = rotate_left(x_i1, 1) if c == 1 else rotate_left(x_i1, 1) & rotate_left(x_i1, 8)
        x_i1 = x_i ^ f ^ rotate_left(x_i1, 2) ^ key[i]
        x_i = tmp

    ct = [x_i, x_i1]
    return ct
from enum import IntEnum, unique

class ProtoError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


@unique
class ProtoFieldType(IntEnum):
    VARINT = 0
    INT64 = 1
    STRING = 2
    GROUPSTART = 3
    GROUPEND = 4
    INT32 = 5
    ERROR1 = 6
    ERROR2 = 7


class ProtoField:
    def __init__(self, idx, type, val):
        self.idx = idx
        self.type = type
        self.val = val

    def isAsciiStr(self):
        if (type(self.val) != bytes):
            return False

        for b in self.val:
            if b < 0x20 or b > 0x7e:
                return False
        return True

    def __str__(self):
        if ((self.type == ProtoFieldType.INT32) or
            (self.type == ProtoFieldType.INT64) or
                (self.type == ProtoFieldType.VARINT)):
            return '%d(%s): %d' % (self.idx, self.type.name, self.val)
        elif self.type == ProtoFieldType.STRING:
            if self.isAsciiStr():  # self.val.isalnum()
                return '%d(%s): "%s"' % (self.idx, self.type.name, self.val.decode('ascii'))
            else:
                return '%d(%s): h"%s"' % (self.idx, self.type.name, self.val.hex())
        elif ((self.type == ProtoFieldType.GROUPSTART) or (self.type == ProtoFieldType.GROUPEND)):
            return '%d(%s): %s' % (self.idx, self.type.name, self.val)
        else:
            return '%d(%s): %s' % (self.idx, self.type.name, self.val)


class ProtoReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def seek(self, pos):
        self.pos = pos

    def isRemain(self, length):
        return self.pos + length <= len(self.data)

    def read0(self):
        assert (self.isRemain(1))
        ret = self.data[self.pos]
        self.pos += 1
        return ret & 0xFF

    def read(self, length):
        assert (self.isRemain(length))
        ret = self.data[self.pos:self.pos+length]
        self.pos += length
        return ret

    def readInt32(self):
        return int.from_bytes(self.read(4), byteorder='little', signed=False)

    def readInt64(self):
        return int.from_bytes(self.read(8), byteorder='little', signed=False)

    def readVarint(self):
        vint = 0
        n = 0
        while True:
            byte = self.read0()
            vint |= ((byte & 0x7F) << (7 * n))
            if byte < 0x80:
                break
            n += 1

        return vint

    def readString(self):
        len = self.readVarint()
        return self.read(len)


class ProtoWriter:
    def __init__(self):
        self.data = bytearray()

    def write0(self, byte):
        self.data.append(byte & 0xFF)

    def write(self, bytes):
        self.data.extend(bytes)

    def writeInt32(self, int32):
        bs = int32.to_bytes(4, byteorder='little', signed=False)
        self.write(bs)

    def writeInt64(self, int64):
        bs = int64.to_bytes(8, byteorder='little', signed=False)
        self.write(bs)

    def writeVarint(self, vint):
        vint = vint & 0xFFFFFFFF
        while (vint > 0x80):
            self.write0((vint & 0x7F) | 0x80)
            vint >>= 7
        self.write0(vint & 0x7F)

    def writeString(self, bytes):
        self.writeVarint(len(bytes))
        self.write(bytes)

    def toBytes(self):
        return bytes(self.data)


class ProtoBuf:
    def __init__(self, data=None):
        self.fields = list[ProtoField]()
        if (data != None):
            if (type(data) != bytes and type(data) != dict):
                raise ProtoError(
                    'unsupport type(%s) to protobuf' % (type(data)))

            if (type(data) == bytes) and (len(data) > 0):
                self.__parseBuf(data)
            elif (type(data) == dict) and (len(data) > 0):
                self.__parseDict(data)

    def __getitem__(self, idx):
        pf = self.get(int(idx))
        if (pf == None):
            return None
        if (pf.type != ProtoFieldType.STRING):
            return pf.val
        if (type(idx) != int):
            return pf.val
        if (pf.val == None):
            return None
        if (pf.isAsciiStr()):
            return pf.val.decode('utf-8')
        return ProtoBuf(pf.val)

    def __parseBuf(self, bytes):
        reader = ProtoReader(bytes)
        while reader.isRemain(1):
            key = reader.readVarint()
            field_type = ProtoFieldType(key & 0x7)
            field_idx = key >> 3
            if (field_idx == 0):
                break
            if (field_type == ProtoFieldType.INT32):
                self.put(ProtoField(field_idx, field_type, reader.readInt32()))
            elif (field_type == ProtoFieldType.INT64):
                self.put(ProtoField(field_idx, field_type, reader.readInt64()))
            elif (field_type == ProtoFieldType.VARINT):
                self.put(ProtoField(field_idx, field_type, reader.readVarint()))
            elif (field_type == ProtoFieldType.STRING):
                self.put(ProtoField(field_idx, field_type, reader.readString()))
            else:
                raise ProtoError(
                    'parse protobuf error, unexpected field type: %s' % (field_type.name))

    def toBuf(self):
        writer = ProtoWriter()
        for field in self.fields:
            key = (field.idx << 3) | (field.type & 7)
            writer.writeVarint(key)
            if field.type == ProtoFieldType.INT32:
                writer.writeInt32(field.val)
            elif field.type == ProtoFieldType.INT64:
                writer.writeInt64(field.val)
            elif field.type == ProtoFieldType.VARINT:
                writer.writeVarint(field.val)
            elif field.type == ProtoFieldType.STRING:
                writer.writeString(field.val)
            else:
                raise ProtoError(
                    'encode to protobuf error, unexpected field type: %s' % (field.type.name))
        return writer.toBytes()

    def dump(self):
        for field in self.fields:
            print(field)

    def getList(self, idx):
        return [field for field in self.fields if field.idx == idx]

    def get(self, idx):
        for field in self.fields:
            if field.idx == idx:
                return field
        return None

    def getInt(self, idx):
        pf = self.get(idx)
        if (pf == None):
            return 0
        if ((pf.type == ProtoFieldType.INT32) or (pf.type == ProtoFieldType.INT64) or (pf.type == ProtoFieldType.VARINT)):
            return pf.val
        raise ProtoError("getInt(%d) -> %s" % (idx, pf.type))

    def getBytes(self, idx):
        pf = self.get(idx)
        if (pf == None):
            return None
        if (pf.type == ProtoFieldType.STRING):
            return pf.val
        raise ProtoError("getBytes(%d) -> %s" % (idx, pf.type))

    def getUtf8(self, idx):
        bs = self.getBytes(idx)
        if (bs == None):
            return None
        return bs.decode('utf-8')

    def getProtoBuf(self, idx):
        bs = self.getBytes(idx)
        if (bs == None):
            return None
        return ProtoBuf(bs)

    def put(self, field: ProtoField):
        self.fields.append(field)

    def putInt32(self, idx, int32):
        self.put(ProtoField(idx, ProtoFieldType.INT32, int32))

    def putInt64(self, idx, int64):
        self.put(ProtoField(idx, ProtoFieldType.INT64, int64))

    def putVarint(self, idx, vint):
        self.put(ProtoField(idx, ProtoFieldType.VARINT, vint))

    def putBytes(self, idx, data):
        self.put(ProtoField(idx, ProtoFieldType.STRING, data))

    def putUtf8(self, idx, data):
        self.put(ProtoField(idx, ProtoFieldType.STRING, data.encode('utf-8')))

    def putProtoBuf(self, idx, data):
        self.put(ProtoField(idx, ProtoFieldType.STRING, data.toBuf()))

    def __parseDict(self, data):
        for k, v in data.items():
            if (isinstance(v, int)):
                self.putVarint(k, v)
            elif (isinstance(v, str)):
                self.putUtf8(k, v)
            elif (isinstance(v, bytes)):
                self.putBytes(k, v)
            elif (isinstance(v, dict)):
                self.putProtoBuf(k, ProtoBuf(v))
            else:
                raise ProtoError('unsupport type(%s) to protobuf' % (type(v)))

    def toDict(self, out):
        for k, v in out.items():
            if (isinstance(v, int)):
                out[k] = self.getInt(k)
            elif (isinstance(v, str)):
                out[k] = self.getUtf8(k)
            elif (isinstance(v, bytes)):
                out[k] = self.getBytes(k)
            elif (isinstance(v, dict)):
                out[k] = self.getProtoBuf(k).toDict(v)
            else:
                raise ProtoError('unsupport type(%s) to protobuf' % (type(v)))
        return out


class Argus:
    def encrypt_enc_pb(data, l):
        data      = list(data)
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
        protobuf    = pkcs7_pad(bytes.fromhex(ProtoBuf(xargus_bean).toBuf().hex()), block_size)
        new_len     = len(protobuf)
        sign_key    = b'\xac\x1a\xda\xae\x95\xa7\xaf\x94\xa5\x11J\xb3\xb3\xa9}\xd8\x00P\xaa\n91L@R\x8c\xae\xc9RV\xc2\x8c'
        sm3_output  = b'\xfcx\xe0\xa9ez\x0ct\x8c\xe5\x15Y\x90<\xcf\x03Q\x0eQ\xd3\xcf\xf22\xd7\x13C\xe8\x8a2\x1cS\x04' #sm3_hash(sign_key + b'\xf2\x81ao' + sign_key)

        key         = sm3_output[:32]
        key_list    = []
        enc_pb      = bytearray(new_len)
        
        for _ in range(2): 
            key_list = key_list + list(unpack("<QQ", key[_ * 16 : _ * 16 + 16]))
        
        for _ in range(int(new_len / 16)):
            pt = list(unpack("<QQ", protobuf[_ * 16 : _ * 16 + 16]))
            ct = simon_enc(pt, key_list)
            enc_pb[_ * 16 : _ * 16 + 8] = ct[0].to_bytes(8, byteorder="little")
            enc_pb[_ * 16 + 8 : _ * 16 + 16] = ct[1].to_bytes(8, byteorder="little")

        b_buffer    = Argus.encrypt_enc_pb((b"\xf2\xf7\xfc\xff\xf2\xf7\xfc\xff" + enc_pb), new_len + 8)
        b_buffer    = b'\xa6n\xad\x9fw\x01\xd0\x0c\x18' + b_buffer + b'ao'
        
        cipher      = new(md5(sign_key[:16]).digest(), MODE_CBC, md5(sign_key[16:]).digest())

        return b64encode(b"\xf2\x81" + cipher.encrypt(pkcs7_pad(b_buffer, block_size))).decode()
    
    @staticmethod
    def get_sign(queryhash          : None or str = None,
                    data            : None or str = None,
                    timestamp       : int = int(time()),
                    aid             : int = 1233,
                    license_id      : int = 1611921764,
                    platform        : int = 0,
                    sec_device_id   : str = "",
                    sdk_version     : str = "v04.04.05-ov-android",
                    sdk_version_int : int = 134744640) -> dict:
        
        params_dict = parse_qs(queryhash)

        p = params_dict['app_version'][0].split('.')
        app_version_hash = bytes.fromhex('{:x}{:x}{:x}00'.format(int(p[2]) * 4, int(p[1]) * 16, int(p[0]) * 4).zfill(8))
        app_version_constant = (int.from_bytes(app_version_hash, byteorder='big') << 1)

        osVersion = params_dict['os_version'][0]
        osVersion = osVersion.split(".") 
        for _ in range(3 - len(osVersion)):
            osVersion.append(0)
        #metaSecConstant = ((int(osVersion[0])-4) + int(osVersion[1])*256 + int(osVersion[2])*4096)*2
        #print(app_version_constant)
        #print(metaSecConstant)

        return Argus.encrypt({
            1: 0x20200929 << 1,                 # magic
            2: 2,                               # version
            3: randint(0, 0x7FFFFFFF),          # rand
            4: str(aid),                        # msAppID
            5: params_dict['device_id'][0],     # deviceID
            6: str(license_id),                 # licenseID
            7: params_dict['app_version'][0],  # appVersion
            8: sdk_version,                     # sdkVersionStr
            9: sdk_version_int,                 # sdkVersion
            10: bytes(8),                       # envcode -> jailbreak Detection 
            #11: platform,                       # platform (ios = 1)
            12: (timestamp << 1),               # createTime
            13: Argus.get_bodyhash(data),       # bodyHash
            14: Argus.get_queryhash(queryhash), # queryHash
            #15: {
            #    1: 270,                           # signCount
            #    2: 4,                           # reportCount
            #    5: 6,                           # settingCount
            #    6: 4,                           # settingCount
            #    7: (timestamp << 1) - 310,
            #},
            16: sec_device_id,                  # secDeviceToken
            #17: (timestamp << 1),               # createTime
            20: "none",                         # pskVersion
            21: 738,                            # callType
            #23: {
            #    1: params_dict['device_type'][0], 
            #    2: metaSecConstant, 
            #    3: 'googleplay', 
            #    4: app_version_constant 
            #},
            25: 2
        })
import hashlib
import json
import time

class Gorgon:
    def __init__(self, params: str, unix: int, data: str = None, cookies: str = None) -> None:
        self.unix = unix
        self.params = params
        self.data = data
        self.cookies = cookies

    def hash(self, data: str) -> str:
        return str(hashlib.md5(data.encode()).hexdigest())

    def get_base_string(self) -> str:
        base_str = self.hash(self.params)
        base_str = (
            base_str + self.hash(self.data) if self.data else base_str + str("0" * 32)
        )
        base_str = (
            base_str + self.hash(self.cookies)
            if self.cookies
            else base_str + str("0" * 32)
        )
        return base_str

    def get_value(self) -> json:
        return self.encrypt(self.get_base_string())

    def encrypt(self, data: str) -> json:
        len = 0x14
        key = [
            0xDF,
            0x77,
            0xB9,
            0x40,
            0xB9,
            0x9B,
            0x84,
            0x83,
            0xD1,
            0xB9,
            0xCB,
            0xD1,
            0xF7,
            0xC2,
            0xB9,
            0x85,
            0xC3,
            0xD0,
            0xFB,
            0xC3,
        ]
        param_list = []
        for i in range(0, 12, 4):
            temp = data[8 * i : 8 * (i + 1)]
            for j in range(4):
                H = int(temp[j * 2 : (j + 1) * 2], 16)
                param_list.append(H)
        param_list.extend([0x0, 0x6, 0xB, 0x1C])
        H = int(hex(int(self.unix)), 16)
        param_list.append((H & 0xFF000000) >> 24)
        param_list.append((H & 0x00FF0000) >> 16)
        param_list.append((H & 0x0000FF00) >> 8)
        param_list.append((H & 0x000000FF) >> 0)
        eor_result_list = []
        for A, B in zip(param_list, key):
            eor_result_list.append(A ^ B)
        for i in range(len):
            C = self.reverse(eor_result_list[i])
            D = eor_result_list[(i + 1) % len]
            E = C ^ D
            F = self.rbit_algorithm(E)
            H = ((F ^ 0xFFFFFFFF) ^ len) & 0xFF
            eor_result_list[i] = H
        result = ""
        
        for param in eor_result_list:
            result += self.hex_string(param)
            
        return {
            "x-ss-req-ticket" : str(int(self.unix * 1000)),
            "x-khronos"       : str(int(self.unix)),
            "x-gorgon"        : f"0404b0d30000{result}"
        }

    def rbit_algorithm(self, num):
        result = ""
        tmp_string = bin(num)[2:]
        while len(tmp_string) < 8:
            tmp_string = "0" + tmp_string
        for i in range(0, 8):
            result = result + tmp_string[7 - i]
        return int(result, 2)

    def hex_string(self, num):
        tmp_string = hex(num)[2:]
        if len(tmp_string) < 2:
            tmp_string = "0" + tmp_string
        return tmp_string

    def reverse(self, num):
        tmp_string = self.hex_string(num)
        return int(tmp_string[1:] + tmp_string[:1], 16)
def pkcs7_padding_data_length(buffer, buffer_size, modulus):
    if buffer_size % modulus != 0 or buffer_size < modulus:
        return 0
    padding_value = buffer[buffer_size-1]
    if padding_value < 1 or padding_value > modulus:
        return 0
    if buffer_size < padding_value + 1:
        return 0
    count = 1
    buffer_size -= 1
    for i in range(count, padding_value):
        buffer_size -= 1
        if buffer[buffer_size] != padding_value:
            return 0
    return buffer_size

def pkcs7_padding_pad_buffer(buffer: bytearray, data_length: int, buffer_size: int, modulus: int) -> int:
    pad_byte = modulus - (data_length % modulus)
    if data_length + pad_byte > buffer_size:
        return -pad_byte
    for i in range(pad_byte):
        buffer[data_length+i] = pad_byte
    return pad_byte

def padding_size(size: int) -> int:
    mod = size % 16
    if mod > 0:
        return size + (16 - mod)
    return size
import base64
import hashlib
import ctypes
from os import urandom

def md5bytes(data: bytes) -> str:
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def get_type_data(ptr, index, data_type):
    if data_type == "uint64_t":
        return int.from_bytes(ptr[index * 8 : (index + 1) * 8], "little")
    else:
        raise ValueError("Invalid data type")


def set_type_data(ptr, index, data, data_type):
    if data_type == "uint64_t":
        ptr[index * 8 : (index + 1) * 8] = data.to_bytes(8, "little")
    else:
        raise ValueError("Invalid data type")


def validate(num):
    return num & 0xFFFFFFFFFFFFFFFF


def __ROR__(value: ctypes.c_ulonglong, count: int) -> ctypes.c_ulonglong:
    nbits = ctypes.sizeof(value) * 8
    count %= nbits
    low = ctypes.c_ulonglong(value.value << (nbits - count)).value
    value = ctypes.c_ulonglong(value.value >> count).value
    value = value | low
    return value


def encrypt_ladon_input(hash_table, input_data):
    data0 = int.from_bytes(input_data[:8], byteorder="little")
    data1 = int.from_bytes(input_data[8:], byteorder="little")

    for i in range(0x22):
        hash = int.from_bytes(hash_table[i * 8 : (i + 1) * 8], byteorder="little")
        data1 = validate(hash ^ (data0 + ((data1 >> 8) | (data1 << (64 - 8)))))
        data0 = validate(data1 ^ ((data0 >> 0x3D) | (data0 << (64 - 0x3D))))

    output_data = bytearray(26)
    output_data[:8] = data0.to_bytes(8, byteorder="little")
    output_data[8:] = data1.to_bytes(8, byteorder="little")

    return bytes(output_data)


def encrypt_ladon(md5hex: bytes, data: bytes, size: int):
    hash_table = bytearray(272 + 16)
    hash_table[:32] = md5hex

    temp = []
    for i in range(4):
        temp.append(int.from_bytes(hash_table[i * 8 : (i + 1) * 8], byteorder="little"))

    buffer_b0 = temp[0]
    buffer_b8 = temp[1]
    temp.pop(0)
    temp.pop(0)

    for i in range(0, 0x22):
        x9 = buffer_b0
        x8 = buffer_b8
        x8 = validate(__ROR__(ctypes.c_ulonglong(x8), 8))
        x8 = validate(x8 + x9)
        x8 = validate(x8 ^ i)
        temp.append(x8)
        x8 = validate(x8 ^ __ROR__(ctypes.c_ulonglong(x9), 61))
        set_type_data(hash_table, i + 1, x8, "uint64_t")
        buffer_b0 = x8
        buffer_b8 = temp[0]
        temp.pop(0)

    new_size = padding_size(size)

    input = bytearray(new_size)
    input[:size] = data
    pkcs7_padding_pad_buffer(input, size, new_size, 16)

    output = bytearray(new_size)
    for i in range(new_size // 16):
        output[i * 16 : (i + 1) * 16] = encrypt_ladon_input(
            hash_table, input[i * 16 : (i + 1) * 16]
        )

    return output


def ladon_encrypt(
    khronos      : int,
    lc_id        : int   = 1611921764,
    aid          : int   = 1233,
    random_bytes : bytes = urandom(4)) -> str:
    
    data       = f"{khronos}-{lc_id}-{aid}"

    keygen     = random_bytes + str(aid).encode()
    md5hex     = md5bytes(keygen)

    size       = len(data)
    new_size   = padding_size(size)

    output     = bytearray(new_size + 4)
    output[:4] = random_bytes

    output[4:] = encrypt_ladon(md5hex.encode(), data.encode(), size)

    return base64.b64encode(bytes(output)).decode()


class Ladon:
    @staticmethod
    def encrypt(x_khronos: int, lc_id: str, aid: int) -> str:
        return ladon_encrypt(x_khronos, lc_id, aid)
from time   import time
from hashlib import md5

def sign(
    params: dict,
    payload: str or None = None,
    sec_device_id: str = '',
    cookie: str or None = None,
    aid: int = None,
    license_id: int = 1611921764,
    sdk_version_str: str = 'v05.00.06-ov-android',
    sdk_version: int = 167775296,
    platform: int = 0,
    unix: float = None
):
    if payload is None:
        payload = ''
    if cookie is None:
        cookie = ''
    if not unix:
        unix = time()
    if aid is None:
        aid = int(params.get('aid', 1233))
    encoded_params = urlencode(params)
    if cookie:
        cookie = urlencode(cookie)
    if payload:
        payload = urlencode(payload)
    x_ss_stub = md5(payload.encode('utf-8')).hexdigest()
    return Gorgon(encoded_params, unix, payload, cookie).get_value() | {
        'content-length': str(len(payload)),
        'x-ss-stub': x_ss_stub.upper(),
        'x-ladon': Ladon.encrypt(int(unix), license_id, aid),
        'x-argus': Argus.get_sign(encoded_params, x_ss_stub, int(unix),
            platform=platform,
            aid=aid,
            license_id=license_id,
            sec_device_id=sec_device_id,
            sdk_version=sdk_version_str,
            sdk_version_int=sdk_version
        )
    }




def xor(string: str) -> str:
        return "".join([hex(ord(_) ^ 5)[2:] for _ in string]) 
        
        
        
def get(params: dict):
    params.update({
    '_rticket': int(round(time() * 1000)),
    'cdid': str(uuid.uuid4()),
    'ts': int(time()),
    'iid': str(random.randint(1, 10**19)),
    'device_id': str(random.randint(1, 10**19)),
    'openudid': str(binascii.hexlify(os.urandom(8)).decode()),
    'app_version': '35.3.2'
})
    return params
    