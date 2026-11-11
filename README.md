# Ephemeral — Phase 0 spike (+ PIN identity and connection requests)

Throwaway prototype for testing the risky assumptions from the Phase 1 architecture **before** the real backend exists. It now also has the first piece of the real product flow: persistent 4-digit PIN identities and PIN-based connection requests, replacing the temporary room codes.

> **Design principle (kept separate on purpose):** the PIN *locates* a user · the HttpOnly recovery cookie *proves to the server* you own that PIN · the E2EE handshake + SAS *authenticates the peer to the other human* · the encrypted session *carries* communication. The server never takes part in the last two.

## What is in here

| Path | What |
|---|---|
| `server/identity_store.py` | **New.** `IdentityStore` interface + SQLite implementation: atomic PIN allocation, cooldown, expiry, exhaustion |
| `server/main.py` | **Rewritten.** `Hub` (connection requests, sessions, relay, abuse limits), `/identity` REST endpoints, WebSocket endpoint, TURN credentials |
| `server/test_identity_store.py`, `test_hub.py`, `test_http.py` | **New.** 68 tests (replace the old room-code `test_main.py`) |
| `client/src/main.ts`, `index.html`, `style.css` | **Changed.** Landing page (My PIN, Connect, incoming modal), status states, SAS-gated chat/calls |
| `client/src/crypto.ts`, `crypto.test.ts` | **Unchanged.** E2EE handshake and transport, 18 tests |
| `e2e/e2e.py` | **Rewritten.** Two independent real Chrome profiles, 47 checks |
| `client/vite.config.ts` | One line: dev proxy now forwards `/identity` |
| `coturn/` | Unchanged, still **untested** |

## Verified in the build sandbox

| Suite | Result | Command |
|---|---|---|
| Crypto unit tests | 18/18 | `cd client && npm test` |
| Server tests (store 15 · hub 30 · HTTP/WebSocket 23) | 68/68 | `cd server && python -m pytest -q` |
| Two-browser end-to-end | 47/47 | `cd e2e && python e2e.py` |

I also **mutation-checked** six security-critical lines (anyone-can-accept, relay trusting a client-supplied target, origin check off, accept not consumed/replay, cooldown ignored, PIN accepted as credential). Each makes at least one test fail. One mutant initially survived (forged `to` field in the relay); the test was tightened and now catches it.

What the end-to-end test proves, in real Chrome with real WebRTC:
- Each browser gets a **different** PIN automatically; **reload keeps it**; a **server restart keeps it**; a **full browser close/relaunch keeps it** (persistent profile).
- The recovery credential is an **HttpOnly, SameSite=Strict** cookie; page JS can't read it; nothing is stored in localStorage/sessionStorage; it never appears in any WebSocket frame.
- Validation (non-digits stripped, exactly 4 digits, own PIN refused), unknown PIN → *Recipient unavailable* (a leading-zero PIN `0000` round-trips), reject → sender told and **no session**, accept → session, incoming modal shows the **sender's PIN**.
- Both sides derive the **same SAS**; chat and calls are **locked until both confirm**; one-sided confirmation does not unlock either side; SAS mismatch ends the session for both.
- Encrypted chat + sealed acks, WebRTC voice with sealed SDP/ICE, and every relayed frame inspected: no chat plaintext, no SDP/ICE, only `{type, seq, ct}` envelopes for `msg`/`sig`.
- LEAVE ends both sides; both **stay online with the same PIN** and can start a new session.

## NOT verified (be skeptical here)

- **Fedora Chrome and Android Chrome.** Only desktop Chrome on Linux ran here. The cross-device procedure below is yours to run.
- **Cookies behind a tunnel/HTTPS.** Tested only on `http://127.0.0.1`. Over `cloudflared`/`ngrok`, two things can bite: the `Secure` cookie flag (needs `TRUST_PROXY=1`) and the **Origin check** if the tunnel rewrites the `Host` header (fix: `ALLOWED_ORIGINS`). Both have unit tests, but neither was exercised through a real tunnel. See *Troubleshooting*.
- **Real concurrency from many machines.** Concurrency is tested with 32 threads against real SQLite connections and with simultaneous `accept` frames, not with real network clients.
- **TURN / relay-only.** Still no coturn or Docker here. Media path in the e2e is `host ↔ host` on loopback.
- **iOS Safari.** Not available.
- **The crypto construction is unreviewed** (unchanged from Phase 0; see below).

## Run it

```bash
# one-time
cd client && npm install && npm run build        # outputs client/dist
cd ../server && pip install -r requirements.txt

# start (serves the built client + API on one origin)
cd server && uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in two **different browser profiles** (or two devices). A normal window and an incognito window are two separate users. Two tabs in the *same* profile are the **same** user (shared cookie) and the second tab takes over the first.

For phones, HTTPS is required for the microphone:

```bash
cloudflared tunnel --url http://localhost:8000    # or: ngrok http 8000
# then restart the server with the proxy settings:
TRUST_PROXY=1 uvicorn main:app --host 0.0.0.0 --port 8000
```

### Environment variables (all optional)

| Variable | Default | Meaning |
|---|---|---|
| `EPHEMERAL_DB` | `ephemeral-identities.db` | SQLite file holding identities. **New.** Delete it to reset all PINs |
| `IDENTITY_TTL_DAYS` | `30` | Idle days before an identity is released. Also the cookie lifetime. **New** |
| `PIN_COOLDOWN_S` | `600` | Seconds a released/expired PIN is withheld from reassignment. **New** |
| `REQUEST_TTL_S` | `60` | How long a connection request stays open. **New** |
| `REJECT_COOLDOWN_S` | `60` | After a reject, the same sender can't re-request that PIN for this long. **New** |
| `SESSION_MAX_S` | `7200` | Hard cap on a session's lifetime. **New** |
| `REGISTER_PER_IP_HOUR` | `20` | New identities per IP per hour. **New** |
| `TRUST_PROXY` | off (`1` = on) | Trust `X-Forwarded-Proto/Host/For` (needed behind a tunnel for the `Secure` cookie flag and correct per-IP limits). **New.** Only enable behind a proxy you control |
| `ALLOWED_ORIGINS` | empty | Comma-separated extra allowed origins, e.g. `https://abc.trycloudflare.com`. **New** |
| `STATIC_DIR`, `STUN_URLS`, `TURN_URLS`, `TURN_SECRET`, `TURN_TTL_S` | | Unchanged |

**New dependencies:** none. SQLite is in the Python standard library.

## How identity works

1. On load the page calls `POST /identity`. With a valid recovery cookie the server returns that identity; otherwise it **atomically allocates** a random free PIN, sets a 256-bit random token as an **HttpOnly; SameSite=Strict** cookie, and stores only `SHA-256(token)`.
2. The WebSocket authenticates from that cookie at handshake (never from the URL, never from JavaScript). The PIN shown on screen is whichever identity the socket actually authenticated as.
3. **PIN alone authenticates nothing.** Presenting a PIN where the cookie belongs just creates a different new identity (tested).
4. One active socket per identity. A second connection **replaces** the first *visibly*: the old one is told (`replaced`, close 4001) and any session it was in is ended, because its keys lived in that tab.
5. Idle identities expire after 30 days into a 10-minute cooldown. Identities that never connect (two tabs racing to register) are reclaimed after 5 minutes without cooldown. **Get a new PIN** (under *Advanced*) releases the current one.

### PIN namespace limits (unchanged from Phase 1)
10,000 values, ~13 bits. Hard ceiling of 10,000 concurrent identities, minus any in cooldown. When full, `POST /identity` returns a controlled `503 {"error":"pins_exhausted"}` with `Retry-After`, never a duplicate PIN.

## Connection requests

| Step | Behaviour |
|---|---|
| Send | Exactly 4 digits (string, leading zeros kept). One outstanding request per sender. Own PIN refused. Token bucket: burst 5, then 1 per 6 s |
| Deliver | Recipient sees the **sender's PIN** and Accept / Reject. A recipient holds at most 3 pending requests |
| Accept | Only the addressed identity can accept; request is consumed atomically; both get the same `sid`; requester is role `a` |
| Reject / expire / cancel | No session. Sender is told `rejected` / `expired` / `cancelled`. After a reject the same sender is silently blocked from that PIN for 60 s |
| Concurrent | Entering a session cancels both parties' other pending requests |

**Anti-enumeration (decision to review):** an offline, nonexistent, busy, full-inbox or recently-rejecting target all produce the *same* sender experience: an immediate "sent" ack, then "Recipient unavailable" after a jittered 0.8–2.0 s. **What this still leaks:** a request that *is* delivered reveals a PIN is online (the sender eventually sees accept, reject, or expiry rather than "unavailable"), and the recipient learns the sender's PIN. Rate limits and the per-recipient cap bound probing but don't eliminate it. If that's too much leakage, the stricter option is to map *reject* to the same "unavailable" answer too, at the cost of worse UX.

## Session establishment

After accept, the server only **introduces** the peers (`session {sid, role, peer}`); it never relays or inspects crypto. Both clients run the unchanged commit-then-reveal X25519 handshake, derive the SAS, and:

- **Chat and calls unlock only after BOTH users confirm the SAS.** Each side sends a sealed `verified` message after confirming; a client drops application messages that arrive before its own confirmation. *Does not match* destroys the session.
- The relay routes frames using **server-side connection state only**. Any `sid`/`to`/`from` field in a frame is ignored (tested with forged fields from an outsider and from a member).

## Abuse and security summary

| Concern | Mitigation | Test |
|---|---|---|
| Duplicate active PINs | `BEGIN IMMEDIATE` + `PRIMARY KEY`; random pick from free set | 200 allocations across 32 threads; 40 attempts across 16 threads vs a 10-PIN namespace |
| Namespace exhaustion | Controlled 503; cooldown counts as occupied | full 10,000 exhaustion incl. `0000` and `9999` |
| PIN as credential | Cookie token required; PIN never authenticates | `test_pin_alone_is_not_a_credential` |
| Token theft via XSS | HttpOnly cookie (JS can't read it); strict CSP; text-only rendering | e2e checks `document.cookie` and storage |
| Cross-site WebSocket hijack / cross-site POST | `Origin` must match `Host` (or `X-Forwarded-Host` if trusted, or `ALLOWED_ORIGINS`); `SameSite=Strict` | cross-origin and `Origin: null` refused |
| Forged WebSocket messages | Session derived server-side; accept/reject only by addressee | forged-routing and unauthorized-accept tests |
| Replay | Request consumed on first accept; replayed accept fails | concurrent triple-accept → exactly one session |
| Request flooding | One outstanding per sender, 3 inbound per target, token bucket, reject cooldown, frame rate limit, 64 KB frame cap | hub + socket tests |
| Stale state | Sweeper expires requests (60 s) and sessions (2 h); disconnect clears everything; replaced sockets are told | fake-clock expiry tests |
| Raw token at rest | Only SHA-256 stored | `test_raw_token_is_never_stored` dumps the DB |

## Deliberate departures from the Phase 1 decisions

These follow directly from the requirements in this feature request. Please confirm them.

| Phase 1 | Now | Why |
|---|---|---|
| **D5:** reload = new identity, no credential persisted | Identity persists via an HttpOnly cookie | You required PINs to survive reloads and browser restarts |
| **D7:** LEAVE burns both identities | LEAVE ends only the **session**; identities and sockets persist | Persistent PINs; sessions remain ephemeral |
| Phase 1 §3: no tokens in browser storage | Token is in a cookie JS can't read, not in storage | Better than `localStorage` against XSS, and survives Safari's 7-day script-storage purge |
| **D3/D4:** chat allowed before SAS, with a banner | Chat locked until **both** confirm the SAS | Your requirement §3.5 |
| **D1:** no Postgres | SQLite behind an `IdentityStore` interface | Persistence needed; swap for Redis/Postgres later by implementing the same 7 methods |

**Known weaknesses to be aware of:** the cookie is the recovery credential, so anyone with the browser profile *is* that user; there is no way to recover a PIN on a new device by design (no accounts). Per-IP registration limits are blunt behind carrier NAT. The server can still see *who requests whom* and when (metadata), and can serve malicious JavaScript (the inherent web-app limit from Phase 1).

## Troubleshooting

- **WebSocket closes immediately (code 1006) through a tunnel:** the Origin check likely rejected it. The server logs `rejected websocket with Origin …`. Set `ALLOWED_ORIGINS=https://your-tunnel-url` (and/or `TRUST_PROXY=1`).
- **PIN changes every reload on HTTPS:** the cookie isn't being kept. Confirm third-party-cookie/privacy settings aren't blocking it, and that you open the tunnel URL directly (not in an iframe).
- **Two devices show the same PIN:** they share a cookie jar (same browser profile). Use separate profiles/devices.
- **"All PINs are currently in use" / "Too many new identities":** namespace exhausted, or the per-IP limit hit (all tunnel users share one IP unless `TRUST_PROXY=1`).

## Device test (Fedora Chrome ↔ Android Chrome)

1. Build and start the server as above, behind a tunnel, with `TRUST_PROXY=1`.
2. Open the tunnel URL on **both** devices. Each should show a different 4-digit PIN within a second or two, status **Online**.
3. On Fedora, type the Android PIN → **Connect**. Android should show a modal with the Fedora PIN. Tap **Accept**.
4. Both screens show a 6-digit code. Read it aloud/compare. Tap **Matches** on both. Chat and **Call** unlock only after both.
5. Chat, then call (grant the microphone). Check *Diagnostics → media path*.
6. **LEAVE** on one. Both should end; tap **Back to start**; PINs are unchanged.
7. Close the browser fully and reopen: the PIN must be the same.
8. Tap **Copy log** on each device and send me the logs (they contain no keys, SDP, ciphertext, message text or PINs), plus device/OS/browser versions.

Background/network-flap tests T4–T9 from the original plan still apply: use *Diagnostics*. New relevant behaviour: if the socket drops mid-session the session is destroyed (no resume yet) but the identity and PIN remain, and the page reconnects automatically.

## Original Phase 0 findings (still relevant)

1. **`libsodium-wrappers@0.7.16` ships a broken ESM entry**; `vite.config.ts` aliases to the CJS build.
2. **CSP needs `'wasm-unsafe-eval'`** for libsodium's WASM (WebAssembly only, not JS `eval`).
3. **Bundle:** ~733 kB raw / ~250 kB gzip, nearly all libsodium. Compare `@noble/*` in Phase 3 if low-end phones are slow.
4. **Signaling is sealed:** SDP/ICE travel inside the E2EE channel, so a malicious relay can't swap DTLS fingerprints without breaking the SAS-authenticated session.
5. **Crypto caveat:** composes libsodium primitives into a custom *protocol*. Claims are limited to confidentiality/integrity, forward secrecy, replay rejection, and peer authentication **only after SAS comparison**. No post-compromise security. Replace with a reviewed protocol or get it reviewed before production.

## Spike-only shortcuts (do not carry into Phase 2)

Single process with in-memory request/session state (a restart ends all sessions, by design: fail closed) · SQLite not Redis · no reconnect/resume of a session · no persistent block list · per-IP limit trusts `X-Forwarded-For` only when `TRUST_PROXY=1` · `unsafe-inline` styles · TURN secret on the command line · no logging policy beyond "don't log secrets".
