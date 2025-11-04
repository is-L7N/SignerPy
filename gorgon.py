from time import time
from hashlib import md5
from copy import deepcopy
from random import choice

class Gorgon:
    def __init__(self, params, unix=None, payload=None, cookie=None):
        self.params = params
        self.payload = payload
        self.cookie = cookie
        self.unix = int(unix) if unix is not None else int(time())

    def get_value(self):
        g = ModernGorgon(params=self.params, data=self.payload, cookies=self.cookie, unix=self.unix)
        return g.generate()

class ModernGorgon:
    def __init__(self, params, unix, data=None, cookies=None):
        self.params = params
        self.data = data
        self.cookies = cookies
        self.unix = int(unix)

    def hex_string(self, num):
        return hex(num)[2:].rjust(2, '0')

    def RBIT(self, num):
        return int(bin(num)[2:].rjust(8, '0')[::-1], 2)

    def reverse(self, num):
        tmp_string = self.hex_string(num)
        return int(tmp_string[1:] + tmp_string[:1], 16)

    def addr_BA8(self, hex_CE0):
        tmp = ''
        hex_BA8 = list(range(256))
        for i in range(256):
            A = tmp if tmp != '' else (hex_BA8[i - 1] if i != 0 else 0)
            B = hex_CE0[i % 8]
            if A == 0x05 and i != 1 and tmp != 0x05:
                A = 0
            C = (A + i + B) % 0x100
            tmp = C if C < i else ''
            hex_BA8[i] = hex_BA8[C]
        return hex_BA8

    def initial(self, debug, hex_BA8):
        tmp_add = []
        tmp_hex = deepcopy(hex_BA8)
        for i in range(0x14):
            A = debug[i]
            B = tmp_add[-1] if tmp_add else 0
            C = (hex_BA8[i + 1] + B) % 0x100
            tmp_add.append(C)
            D = tmp_hex[C]
            tmp_hex[i + 1] = D
            E = (D + D) % 0x100
            F = tmp_hex[E]
            debug[i] = A ^ F
        return debug

    def calculate(self, debug):
        for i in range(0x14):
            A = debug[i]
            B = self.reverse(A)
            C = debug[(i + 1) % 0x14]
            D = B ^ C
            E = self.RBIT(D)
            F = E ^ 0x14
            G = (~F + (1 << 32)) % (1 << 32)
            debug[i] = int(hex(G)[-2:], 16)
        return debug

    def generate(self):
        gorgon = []

        url_md5 = md5(self.params.encode('utf-8') if isinstance(self.params, str) else str(self.params).encode('utf-8')).hexdigest()
        gorgon += [int(url_md5[i*2:i*2+2],16) for i in range(4)]

        if self.data:
            if isinstance(self.data, str):
                data_bytes = self.data.encode('utf-8')
            elif isinstance(self.data, bytes):
                data_bytes = self.data
            else:
                data_bytes = str(self.data).encode('utf-8')
            data_md5 = md5(data_bytes).hexdigest()
            gorgon += [int(data_md5[i*2:i*2+2],16) for i in range(4)]
        else:
            gorgon += [0x0]*4

        if self.cookies:
            cookie_md5 = md5(self.cookies.encode('utf-8') if isinstance(self.cookies, str) else str(self.cookies).encode('utf-8')).hexdigest()
            gorgon += [int(cookie_md5[i*2:i*2+2],16) for i in range(4)]
        else:
            gorgon += [0x0]*4

        gorgon += [0x1,0x1,0x2,0x4]

        Khronos = hex(int(self.unix))[2:]
        Khronos = Khronos.rjust(8,'0')
        gorgon += [int(Khronos[i*2:i*2+2],16) for i in range(4)]

        xg = XG(gorgon)
        return {
            "x-ss-req-ticket": str(int(self.unix*1000)),
            "x-khronos": str(int(self.unix)),
            "x-gorgon": xg.main()
        }

class XG:
    def __init__(self, debug):
        self.debug = debug
        self.length = 0x14
        self.hex_CE0 = [0x05,0x00,0x50,choice(range(0,0xFF)),0x47,0x1e,0x00,choice(range(0,0xFF))&0xf0]

    def hex_string(self, num):
        return hex(num)[2:].rjust(2,'0')

    def RBIT(self, num):
        return int(bin(num)[2:].rjust(8,'0')[::-1],2)

    def reverse(self, num):
        tmp_string = self.hex_string(num)
        return int(tmp_string[1:]+tmp_string[:1],16)

    def addr_BA8(self):
        tmp = ''
        hex_BA8 = list(range(256))
        for i in range(256):
            A = tmp if tmp != '' else (hex_BA8[i-1] if i!=0 else 0)
            B = self.hex_CE0[i%8]
            if A==0x05 and i!=1 and tmp!=0x05:
                A=0
            C=(A+i+B)%0x100
            tmp = C if C<i else ''
            hex_BA8[i]=hex_BA8[C]
        return hex_BA8

    def initial(self, debug, hex_BA8):
        tmp_add=[]
        tmp_hex = deepcopy(hex_BA8)
        for i in range(self.length):
            A=debug[i]
            B=tmp_add[-1] if tmp_add else 0
            C=(hex_BA8[i+1]+B)%0x100
            tmp_add.append(C)
            D=tmp_hex[C]
            tmp_hex[i+1]=D
            E=(D+D)%0x100
            F=tmp_hex[E]
            debug[i]=A^F
        return debug

    def calculate(self, debug):
        for i in range(self.length):
            A=debug[i]
            B=self.reverse(A)
            C=debug[(i+1)%self.length]
            D=B^C
            E=self.RBIT(D)
            F=E^self.length
            G=(~F+(1<<32))%(1<<32)
            debug[i]=int(hex(G)[-2:],16)
        return debug

    def main(self):
        result=''
        for item in self.calculate(self.initial(self.debug,self.addr_BA8())):
            result+=self.hex_string(item)
        return '8404{}{}{}{}{}'.format(
            self.hex_string(self.hex_CE0[7]),
            self.hex_string(self.hex_CE0[3]),
            self.hex_string(self.hex_CE0[1]),
            self.hex_string(self.hex_CE0[6]),
            result
        )