# Crypto.com Bug Bounty — Scope
# Program: https://hackerone.com/crypto/policy_scopes
# Date: 2026-04-10

## WEB PROPERTIES

| Asset                                    | Notes                                      |
|------------------------------------------|--------------------------------------------|
| *.crypto.com                             | All subdomains (wildcard)                  |
| *.mona.co                                | All subdomains (wildcard)                  |
| https://crypto.com/exchange              | Exchange trading platform                  |
| https://crypto.com/nft                   | NFT marketplace                            |
| https://crypto.com/price                 | Price tracker                              |
| tax.crypto.com                           | Crypto tax tool                            |
| merchant.crypto.com                      | Merchant payment processing                |
| js.crypto.com                            | JS delivery / CDN assets                   |
| web.crypto.com                           | Web app                                    |
| app.mona.co                              | Mona web app                               |
| developer.crypto.com                     | Developer portal                           |
| developer-api.crypto.com                 | Developer API                              |
| developer-platform-api.crypto.com        | Developer platform API                     |
| nadex.com                                | Derivatives exchange (acquired)            |
| og.com                                   | Acquired domain                            |

## MOBILE APPS (Android)

| Package                  | App                            |
|--------------------------|--------------------------------|
| co.mona.android          | Mona Android app               |
| com.monaco.mobile        | Crypto.com (old Monaco) app    |
| com.defi.wallet          | Crypto.com DeFi Wallet         |

## APIs (Authenticated)

- Crypto.com mobile app APIs that require an account
- Crypto.com Exchange APIs that require an account

## SMART CONTRACTS / BLOCKCHAIN

| Asset                                                                      | Notes                     |
|----------------------------------------------------------------------------|---------------------------|
| https://github.com/crypto-com/cro-staking                                  | CRO staking contracts     |
| https://github.com/crypto-com/swap-contracts-periphery                     | DEX swap periphery        |
| https://github.com/crypto-com/swap-contracts-core                          | DEX swap core             |
| https://github.com/crypto-com/chain-desktop-wallet                         | Desktop wallet app        |
| https://etherscan.io/token/0xfe18ae03741a5b84e39c295ac9c856ed7991c38e     | CRO ERC-20 token contract |
| Crypto.com Wallet Extension                                                 | Browser extension wallet  |

## ATTACK SURFACE PRIORITY

1. Exchange APIs (authenticated) — financial impact potential
2. DeFi Wallet / mobile app APIs — account takeover, fund theft vectors
3. Smart contracts — on-chain bugs (high value if found)
4. *.crypto.com web properties — XSS, IDOR, auth issues
5. developer-api.crypto.com — API key abuse, scope escalation
6. tax.crypto.com / merchant.crypto.com — PII, payment data
