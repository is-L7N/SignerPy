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
```

### 2. Sign Headers

```python
from SignerPy import sign

headers = sign(params=params, payload='your_post_data_here')
```

## Notes

- This library is built for private research and educational use.
- TikTok may change their signing algorithm at any time.

## License

MIT License