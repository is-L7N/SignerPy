# SignerPy

**SignerPy** is a lightweight Python library for generating signed headers and parameters for TikTok's internal API.

## Features

- Generate `x-argus`, `x-ladon`, `x-ss-stub`, and `gorgon` headers.
- Supports signing both GET and POST requests.
- Automatically fills essential TikTok parameters like `_rticket`, `ts`, `iid`, and `device_id`.

## Installation

Place `SignerPy.py` in your project directory and import the methods:

```python
from SignerPy import sign, get
```

## Usage

### 1. Generate Parameters

```python
from SignerPy import get

params = get({
    "device_platform": "android",
    "aid": 1233
})

# just put the original params and the library generate new params !
```

### 2. Sign Headers

```python
from SignerPy import sign

signature = sign(params=params)
# if the request need payload, cookie you can do:
signature = sign(params=params, payload=payload, cookie=cookie)

# and just write

headers.update({
    'x-ss-req-ticket': signature['x-ss-req-ticket'],
    'x-argus': signature["x-argus"],
    'x-gorgon': signature["x-gorgon"],
    'x-khronos': signature["x-khronos"],
    'x-ladon': signature["x-ladon"],
    })


```

## Notes

- This library is built for private research and educational use.
- TikTok may change their signing algorithm at any time.

## License

MIT License
