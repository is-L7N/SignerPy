from .argus  import *
from .ladon  import *
from .gorgon import *
from SignerPy import md5, ladon, argus, gorgon
from random import choice
from urllib.parse import urlencode
import hmac, uuid, random, binascii, os, secrets, time, hashlib
from typing import Union


def sign(params: str or None= None, url: str or None = None,data:str or None =None,payload: str or None = None, sec_device_id: str = '', cookie: str or None = None, aid: int = 1233, license_id: int = 1611921764, sdk_version_str: str = 'v05.00.06-ov-android', sdk_version: int = 167775296, platform: int = 0, unix: float = None):
    x_ss_stub = md5(payload.encode('utf-8')).hexdigest() if payload != None else None   
    if data is None and payload is not None:
    	data = payload
    elif payload is None and data is not None:
    	payload = data
    if params is None and url:
        url, param_str = url.split('?', 1)
        params = dict(p.split('=') for p in param_str.split('&'))
    elif params is None:
        params = {}

    if data is None:
        data = ''
    if cookie is None:
        cookie = ''
    if not unix:
        unix = time.time()
    if aid is None:
        aid = int(params.get('aid', 1233))
       
    if params:
    	params = urlencode(params)
    if cookie:
        cookie = urlencode(cookie)
    if data:
	    if isinstance(data, dict):
	        data = urlencode(data)
	    elif isinstance(data, str):
	        pass
	    else:
	        data = str(data)
    else:
    	data = ""
    x_ss_stub = md5(data.encode('utf-8')).hexdigest()
    return {
        **Gorgon(params, unix, payload, cookie).get_value(),
        'content-length': str(len(payload)) if payload else '0',
        'x-ss-stub': x_ss_stub.upper() if x_ss_stub else '',
        'x-ladon': Ladon.encrypt(int(unix), license_id, aid),
        'x-argus': Argus.get_sign(
            params, 
            x_ss_stub, 
            int(unix),
            platform=platform,
            aid=aid,
            license_id=license_id,
            sec_device_id=sec_device_id,
            sdk_version=sdk_version_str, 
            sdk_version_int=sdk_version
        )
    }

def toHexStr(num: int) -> str:
    tmp_string = hex(num)[2:]
    if len(tmp_string) < 2:
        tmp_string = '0' + tmp_string
    return tmp_string

def trace_id(device_id: Union[str, int] = "") -> str:
    if device_id == "":
        device_id = str(round(time.time()*1000)).zfill(9)
    e = toHexStr(round(time.time()*1000) % 4294967295)
    e = e.zfill(8)
    if type(device_id) == int:
        r = "01"
    else:
        device_id = device_id.replace("-", "")
        r = int(device_id)
    e2 = toHexStr(r)
    r = 22 - len(e2) - 4
    c = str(len(e2)).zfill(2)
    seed = toHexStr(round(random.random() * pow(10, 12)))[0:r]
    c = c+e2+seed
    e3 = e+c
    e3_1 = e3[0:16]
    res = f"00-{e3}-{e3_1}-01"
    return res
    
def md5stub(body) -> str:
    try:
        return (hashlib.md5(body).hexdigest()).upper()
    except:
        return (hashlib.md5(body.encode()).hexdigest()).upper()
                        
def xor(string: str) -> str:
        return "".join([hex(ord(_) ^ 5)[2:] for _ in string])             

def get(params: dict):
    params.update({
    '_rticket': int(round(time.time() * 1000)),
    'cdid': str(uuid.uuid4()),
    'ts': int(time.time()),
    'iid': str(random.randint(1, 10**19)),
    'device_id': str(random.randint(1, 10**19)),
    'openudid': str(binascii.hexlify(os.urandom(8)).decode()),
    'app_version': '35.3.2'
})
    return params
      

def xtoken(params=None, sessionid=None, ms_token=None, ts_millis=False, version_suffix="3.0.0"):

    if params and "ts" in params:
        ts = str(params["ts"])
    else:
        ts = str(int(time.time() * 1000)) if ts_millis else str(int(time.time()))
    
    if sessionid is None:
        key = secrets.token_bytes(32)
    elif isinstance(sessionid, bytes):
        key = sessionid
    else:
        try:
            key = bytes.fromhex(sessionid.strip())
        except:
            key = sessionid.encode('utf-8')
    
    ms = ms_token if ms_token else secrets.token_hex(32)

    parts = [ms, ts]
    if params:
        device_id = params.get("device_id")
        app_version = params.get("app_version")
        if device_id:
            parts.append(str(device_id))
        if app_version:
            parts.append(str(app_version))
    
    _bytes = ("|".join(parts)).encode('utf-8') + key
    sig = hmac.new(key, _bytes, hashlib.sha256).hexdigest()
    

    return f"{ms}--{sig}-{version_suffix}"
#L7N 🇮🇶
