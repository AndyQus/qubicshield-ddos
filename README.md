# QubicShield — Economic Spam Shield via Refundable Deposit

**Status:** Proof of Concept — TypeScript SDK integrated, ready for Testnet Deploy  
**Tagline:** "Make API abuse economically irrational — zero fees, instant refund on Qubic"  
**Technology:** Qubic Smart Contract (C++/QPI), Web Proxy (Node.js/Express), TypeScript

> **Note on scope:** QubicShield protects authenticated API access through economic incentives.
> It is not a network-layer DDoS mitigation (see [open point #9](#open-points--feedback-from-core-developer-2026-04-10) and the [long-term vision](docs/gedanken/vision-dezentrales-ddos-netz.md)).

→ **[Read the full concept & vision](CONCEPT.md)**

---

## Screenshots

| Home  | Simulation | Dashboard |
|---|---|---|
| ![AHome](docs/screenshots/home.png) | ![Simulation](docs/screenshots/simulation.png) | ![Dashboard](docs/screenshots/dashboard.png) |

---

## The Idea

A user pays a small QUBIC deposit to gain access to a website.
When they leave cleanly, the deposit is immediately refunded.
An attacker launching millions of requests would need to pay a deposit for each one —
once an attack is detected, all deposits are forfeited.

**Why Qubic?**  
On Ethereum, gas fees make refunds more expensive than the deposit itself.
Qubic's zero-fee architecture is the only blockchain where this model is economically viable.

## How It Works

```
User                    Qubic Smart Contract        Web Server
  |                            |                        |
  | (0. derive keys from seed — local, never sent to server)
  |-- pays deposit + publicKey →|                       |
  |                            |-- holds deposit         |
  |                            |-- stores publicKey      |
  |                            |-- issues access token   |
  |-- token + SchnorrQ signature ─────────────────────→ |
  |                                  verifies signature  |
  |                                  (publicKey from SC) |
  |←── Access granted ─────────────────────────────── |
  [... each request signed with private key ...]
  |-- clean exit ------------->|                        |
  |                            |-- refunds deposit      |
  |<-- 10 QUBIC returned ------|

On attack:
  Attacker: 1,000,000 requests → needs 1,000,000 × deposit upfront
  → attack detected + signatures verified → deposits forfeited → revenue for operator

Note: signing uses X-QS-Nonce + X-QS-Timestamp + X-QS-Signature headers.
      A stolen token without the private key cannot forge valid signatures.
      REQUIRE_SIGNING=false (default) allows token-only mode for backwards compatibility.
```

## Research Status (verified 2026-03-27)

| Approach | Exists? |
|---|---|
| This concept as a finished product | No — not found anywhere |
| On Qubic | No |
| On Ethereum/EVM | No (gas fees make it uneconomical) |
| Lightning Network | Similar idea (HTLCs), but no web proxy product |
| Classic DDoS protection (Cloudflare etc.) | Yes, but without a crypto deposit model |

Origin of idea: related to Hashcash (Adam Back, 1997) and Lightning HTLC concepts,
but not realized as a complete web product anywhere.

## Architecture

### 1. Qubic Smart Contract (`QubicShield.h`)
Holds deposits on-chain and enforces all rules — no server, no trust required.

| Entry Point | Type | Description |
|---|---|---|
| `Deposit(amount)` | Procedure | Accept QUBIC, issue session token |
| `Refund(index, token)` | Procedure | Return QUBIC to legitimate user |
| `Forfeit(index)` | Procedure | Operator forfeits attacker deposit |
| `ValidateSession(token)` | Function | Proxy checks token validity |
| `GetStats()` | Function | Aggregate statistics |
| `WithdrawForfeited()` | Procedure | Operator withdraws forfeited QUBIC |
| `SetCreatorAddress(id)` | Procedure | Set/update creator wallet |
| `SetOperator(id)` | Procedure | Transfer operator role |

Session expiry runs automatically in the `BEGIN_TICK` hook (> 2× per second, interval < 1s).  
`END_EPOCH` distributes forfeited QUBIC: **35% burned / 40% to the attacked operator / 20% to shareholders / 5% to platform**.  
No shareholder/platform share by design — if there are no DDoS attacks, there is no distribution.

### 2. Web Proxy / Demo Server (`src/server.ts`)
Node.js/Express server. Supports two backends via `USE_REAL_SC` environment variable:

| Mode | Command | Description |
|---|---|---|
| Mock (default) | `npm run dev` | In-memory mock, no blockchain required |
| Real SC | `USE_REAL_SC=true npm run dev` | Calls deployed contract via Qubic RPC |

| Route | Description |
|---|---|
| `POST /api/deposit` | Create deposit |
| `GET /api/validate/:token` | Validate token |
| `POST /api/refund` | Refund deposit |
| `GET /api/protected` | Access protected resource |
| `GET /api/stats` | System statistics |

### 3. TypeScript SDK Client (`src/scClient.ts`)
Wraps `@qubic-lib/qubic-ts-library` v0.1.6 to call the deployed SC:
- Procedures: builds, signs and broadcasts `QubicTransaction` via `POST /v1/broadcast-transaction`
- Functions: sends Base64-encoded payload via `POST /v1/querySmartContract`

### 4. Frontend (`public/`)

| URL | Description |
|---|---|
| `http://localhost:3000/` | API Tester — Deposit, Token, Refund, attack simulation |
| `http://localhost:3000/demo.html` | Fully automated simulation (in the browser) |
| `http://localhost:3000/dashboard.html` | Live dashboard — sessions, events, statistics |

All pages share a unified navigation bar (Home · Simulation · Dashboard), a server status badge (green/red), and a DE/EN language switcher.

### 5. Documentation
- `index.html` — interactive bilingual guide (DE/EN), 18 sections
- `docs/lernjournal-smart-contract.md` — detailed learning journal (DE), 20 chapters (not included in repository)

## Configurable Parameters

```cpp
MAX_DEPOSITS            512     // max concurrent sessions
SESSION_DURATION_TICKS  3600    // < 30 minutes (> 2 ticks/sec, interval < 1s)
MIN_DEPOSIT_AMOUNT      10      // minimum deposit in QUBIC units
```

## Risks & Open Questions

### Product / Legal
- **UX barrier:** Users need a wallet — high friction for mainstream adoption
- **Legal:** Forfeit conditions must be covered in Terms of Service
- **Patent:** Verify whether similar concepts are patented
- **QUBIC price volatility:** Deposit value fluctuates → consider USD-pegged deposit logic
- **False positives:** A legitimate user could be misidentified as an attacker and lose their deposit. No dispute or appeal mechanism exists yet.

### Known Technical Problems

**1. Epoch change (every Wednesday ~12:00 UTC)**  
The Qubic network restarts during each weekly epoch transition. This can take up to 45 minutes. The current retry logic in `scClient.ts` covers only 5 × 8 s = 40 seconds — far too short. During the full outage window the server returns 502 errors. No degraded-mode fallback (e.g. continuing with mock validation) is implemented. The Qubic team is working on reducing this downtime.

**2. Empty ticks (silent transaction drop)**  
Qubic ticks occasionally produce no block. A transaction broadcast to such a tick is silently discarded. `scClient.ts` detects stale ticks server-side and retries up to 5 times. However, the client receives only a `txId` and must poll `/api/validate/<token>` manually. If all retries land in empty ticks the deposit never confirms and the user is stuck waiting with no automatic recovery.

**3. On-chain Forfeit not called in SC mode** ⚠️ Testnet blocker  
Attack detection runs locally in the server. When an attack is detected, `depositManager.forfeitDeposit()` updates only the mock state — the `Forfeit()` procedure on the smart contract is never invoked. In SC mode an attacker keeps their deposit on-chain regardless of the detected attack. This must be implemented before a meaningful testnet test.


**5. Session slot limit**  
`MAX_DEPOSITS = 512` is a PoC value. When all slots are occupied, new deposits are rejected with a cryptic error code. No queue, overflow strategy, or user-facing message is implemented.

**6. Event log unavailable in SC mode**  
`GET /api/events` only works in mock mode. In real SC mode there is no audit trail of deposits, refunds, or forfeit decisions.

---

### Open Points — Feedback from Core Developer (2026-04-10)

**[OPEN] 7. Token theft — static token is not bound to the caller's identity**  
The access token is a static secret transmitted as a `Bearer` token in every HTTP request.
Anyone who intercepts the traffic (MITM without HTTPS) or gains access to server logs can
reuse the token. A stolen token is indistinguishable from the legitimate one.

**Root cause:** The token only proves knowledge of a secret, not ownership of a wallet.

**Planned fix:** Every request must carry a short-lived cryptographic signature produced by
the user's Qubic private key: `sig = Sign(token + nonce + timestamp)`. The server (or SC)
verifies the signature against the wallet's public key stored at deposit time. A stolen token
without the private key is useless.

*Status: **fixed** — Per-request SchnorrQ signing implemented end-to-end:*
- *`src/requestSigner.ts` — shared sign/verify logic using `schnorrq` + `K12` from `@qubic-lib/qubic-ts-library`*
- *`src/browser/qsign.ts` — browser-side signing utility (bundled via esbuild → `public/qsign.js`)*
- *`src/middleware/requestVerifier.ts` — Express middleware: verifies timestamp, nonce (replay protection), SchnorrQ signature*
- *`src/depositManager.ts` — stores 32-byte `publicKey` per session; tracks `usedNonces` per session*
- *`src/server.ts` — accepts optional `publicKey` hex on deposit; applies `requestVerifier` before `requireValidToken` on `/api/protected`*
- *`public/index.html` — Seed input (never sent to server); `QSign.init(seed)` derives keys; `QSign.signedHeaders(token)` builds signed request headers*
- *Backwards-compatible: `REQUIRE_SIGNING=false` (default) allows token-only requests; set `REQUIRE_SIGNING=true` to enforce signing in production*
- *Build browser bundle: `npm run build:browser`*

---

**[OPEN] 8. Refund authorization — anyone who knows the token can trigger a refund**  
`Refund()` in `QubicShield.h` verifies `entry.token == input.token` but does **not** check
`qpi.invocator() == entry.owner`. This means any party who obtains the token and session index
(e.g. the web server operator) can trigger a refund to the original depositor's wallet
— or could be extended by an attacker to drain sessions they don't own.

**Planned fix:** Add `if (qpi.invocator() != entry.owner)` guard at the top of `PUBLIC_PROCEDURE(Refund)`.
This ensures only the original depositor can request their own refund.

*Status: **fixed** — `qpi.invocator() != entry.owner` guard added to `PUBLIC_PROCEDURE(Refund)` in `QubicShield.h`. Mock (`depositManager.ts`) updated: `refundDeposit()` now accepts optional `callerWallet` and rejects mismatches. `server.ts` passes `walletAddress` from request body to the mock check.*

---

**[OPEN] 9. Not actual DDoS protection — unauthenticated traffic still reaches the server**  
The deposit model only protects the authenticated code path. An attacker sending millions of
requests *without* a token still causes the server to accept TCP connections, parse HTTP headers,
and return 401 responses — which is enough to exhaust server resources.

**What QubicShield actually solves:** Economic spam prevention for *authenticated* API access.
It is not a replacement for network-layer DDoS mitigation (Cloudflare, Anycast, BGP filtering).

**Long-term vision:** Qubic as the economic backbone of a decentralized shield-node network
that filters traffic *before* it reaches the origin server.
See [`docs/gedanken/vision-dezentrales-ddos-netz.md`](docs/gedanken/vision-dezentrales-ddos-netz.md).

*Status: **partially addressed** — project title and tagline updated to "Economic Spam Shield". A scope note has been added at the top of the README. The long-term architectural path is documented in [`docs/gedanken/vision-dezentrales-ddos-netz.md`](docs/gedanken/vision-dezentrales-ddos-netz.md).*

## Getting Started

```bash
# Clone repository and install dependencies
git clone <repo-url>
cd qubicshield
npm install

# Run tests (all 56 must pass)
npm test

# Start development server
npm run dev
# → http://localhost:3000
```

A green badge in the top-right corner of each page confirms the server is running.

### Console Demo (optional, second terminal)

```bash
# Terminal 1 — start server
npm run dev

# Terminal 2 — run console demo (requires running server)
npm run demo
```

`npm run demo` simulates the full flow: create deposit → validate token → access protected route → request refund → DDoS attack → forfeit → statistics.

### Real SC Mode (after testnet deploy)

Create `.env` with the values from the deploy:

```env
SC_ADDRESS=<60-char contract public ID>
SC_INDEX=<numeric contract index>
QUBIC_RPC=https://testnet-rpc.qubic.org
```

Then run:

```bash
USE_REAL_SC=true npm run dev
```

## GitHub Pages

The interactive guide is available at: **https://andyqus.github.io/qubicshield/**

The root `index.html` is a static file and works on GitHub Pages without any server.  
Enable Pages in your repository settings (Source: `main` branch, root `/`) — done.

> **Note:** The web app under `public/` (API Tester, Simulation, Dashboard) requires the running Express server for all API calls. These pages render on GitHub Pages but all API interactions will fail without the server.

## Next Steps

### Before testnet deploy
- [ ] Implement on-chain `Forfeit()` call in `server.ts` when attack is detected
- [ ] Contact Qubic community / team — present the project in Discord (#developers), gather feedback, clarify testnet deploy process

### Testnet
- [ ] Deploy `QubicShield.h` to Qubic testnet
- [ ] Set `SC_ADDRESS` and `SC_INDEX` in `.env`
- [ ] Run end-to-end tests against the deployed contract

### Production readiness
- [ ] Extend retry window for epoch transitions (> 45 min) or implement degraded-mode fallback
- [ ] Implement server-side deposit confirmation polling so clients don't need to manage retries
- [ ] Add false-positive dispute / appeal mechanism
- [ ] Raise `MAX_DEPOSITS` beyond 512 and add overflow handling
- [ ] Implement event log for SC mode (on-chain audit trail)

## Sources
- [Qubic QPI Documentation](https://docs.qubic.org/developers/qpi/)
- [Hashcash — Adam Back, 1997](http://www.hashcash.org/papers/hashcash.pdf)
- [Lightning Network HTLCs](https://lightning.network/lightning-network-paper.pdf)

## License

As we use parts from the 451 Package (`@qubic-lib/qubic-ts-library`) for Qubic transaction signing and broadcasting, the Anti-Military License also applies. See https://github.com/computor-tools/qubic-crypto

The QubicShield source code (Smart Contract, Web Proxy, TypeScript SDK) is licensed under the AGPL-3.0 License. You may use our source code for what you need to do business.
