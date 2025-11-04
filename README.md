# SignerPy Utility Library 
# New Update 8404 Gorgon and more

![Python](https://img.shields.io/badge/Python-3.10-blue)

SignerPy is a Python library that provides various tools for encryption, signing, URL parsing, token generation, and more, mainly designed for interacting with TikTok APIs.

---

## Table of Contents
- [Installation](#installation)
- [Modules](#modules)
- [Usage Examples](#usage-examples)
- [Output Samples](#output-samples)

---

## Installation

```bash
pip install SignerPy==0.8
git clone https://github.com/is-L7N/SignerPy.git
cd SignerPy

```

---

## Modules

SignerPy contains the following modules:

| Module | Description |
|--------|-------------|
| `encryption` | Provides `enc` and `dec` functions for encryption/decryption. |
| `hosts` | Returns a list of TikTok API hosts using `host()`. |
| `xor` | Simple XOR encoding of strings. |
| `url_to_params` | Parses a URL query string into a dictionary using `dicts()`. |
| `xtoken` | Generates `x-token` values for API requests. |
| `trace_id` | Generates a trace ID for TikTok devices. |
| `sign` | Generates request signatures. |
| `md5stub` | Generates MD5 hash of a string or body. |
| `ttencrypt` | Provides advanced encryption (`Enc().encrypt()`). |
| `*` | Imports all functions for easy access. |

---

## Usage Examples

### Encryption & Decryption

```python
from SignerPy.encryption import enc, dec

data = {
    "aid": "1988",
    "app_name": "tiktok_web",
    "device_platform": "web_pc"
}

encrypted = enc(data)
print(encrypted)

decrypted = dec(encrypted)
print(decrypted)
```

**Sample Output:**

```json
{
  "aid": "1988",
  "app_name": "tiktok_web",
  "device_platform": "web_pc"
}
```

### Hosts

```python
from SignerPy.hosts import host

print(host())
```

**Sample Output:**

```
['api16-normal-no1a.tiktokv.eu', 'api16-normal-c-alisg.tiktokv.com', ...]
```

### XOR Encoding

```python
from SignerPy import xor

encoded = xor("email or username")
print(encoded)
```

**Sample Output:**

```
6068646c69256a7725707660776b646860
```

### URL to Dictionary

```python
from SignerPy.url_to_params import dicts

url = "https://api16-normal-c-alisg.tiktokv.com/lite/v2/public/item/list/?source=0&sec_user_id=XXXXX"
params = dicts(url=url)
print(params)
```

**Sample Output:**

```json
{
  "source": "0",
  "sec_user_id": "XXXXX",
  "count": "9",
  "app_name": "musically_go"
}
```

### XToken

```python
from SignerPy import xtoken

x_token = xtoken(params="", sessionid="")
print(x_token)
```

**Sample Output:**

```
7a3465ad525ddf8ba13bc005d45c99a0f480a503b4c3b2a3f5aa184cdb332102--...
```

### Trace ID

```python
from SignerPy import trace_id

trace = trace_id(device_id="1234567890")
print(trace)
```

**Sample Output:**

```
00-4eee0edf08499602d2277ea43fe8-4eee0edf08499602-01
```

### MD5 Hash

```python
from SignerPy import md5stub

hash_value = md5stub(body="username=L7N")
print(hash_value)
```

**Sample Output:**

```
866F9F9C270106B1AF8063FFD0A80A22
```

### TTEncrypt

```python
from SignerPy import ttencrypt

encrypted = ttencrypt.Enc().encrypt(data="username=L7N")
print(encrypted)
```

**Sample Output:**

```
b'tc\x05\x10\x00\x00\x1c^\xe4\xa6...'
```

## ✍️ Author
- [![Telegram](https://img.shields.io/badge/Telegram-PyL7N-0088cc?style=flat-square&logo=telegram)](https://t.me/PyLast)
- [![GitHub](https://img.shields.io/badge/GitHub-is--L7N-181717?style=flat-square&logo=github)](https://github.com/is-L7N)

---
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Author-L7N-blue?style=flat-square" alt="author">
  <img src="https://img.shields.io/badge/Language-Python-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Working-success?style=flat-square">
</p>

---


