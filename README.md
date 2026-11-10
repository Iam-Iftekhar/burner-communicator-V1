# Ephemeral — Phase 0 Spike

Throwaway prototype that tests the riskiest assumptions from the Phase 1 architecture **before** any backend is built:

1. Does the SAS-authenticated E2EE handshake + sealed signaling work in real browsers?
2. Does WebRTC voice work with SDP/ICE sent only as ciphertext?
3. How badly do iOS Safari and Android Chrome treat a backgrounded session? (This decides D5/D6 and whether the web-app approach is viable on mobile.)
4. Does TURN relay-only mode work (hides peer IPs)?

It is **not** the product: room codes instead of PINs, no Redis, no identity/session tokens, no reconnect, no PoW.

## What is in here

| Path | What |
|---|---|
| `client/src/crypto.ts` | Transport-agnostic E2EE session: commit-reveal SAS handshake, ratcheted XChaCha20-Poly1305, bucket padding, replay rejection, zeroization |
| `client/src/main.ts` | Vanilla-TS UI: create/join, SAS compare, chat with sealed acks, voice call with sealed SDP/ICE, LEAVE, diagnostics |
| `server/main.py` | FastAPI relay: pairs 2 sockets, relays opaque frames, destroys room on leave/disconnect, issues TURN REST credentials |
| `coturn/` | TURN config (**untested**, see below) |
| `e2e/e2e.py` | Two-real-Chrome end-to-end test |

## Verified in the build sandbox (all passing)

| Suite | Result | Command |
|---|---|---|
| Crypto unit tests (vitest) | 18/18 | `cd client && npm test` |
| Relay server tests (pytest) | 13/13 | `cd server && python -m pytest -q` |
| Two-browser end-to-end (real Chrome, real WebRTC, fake mics) | 20/20 | `cd e2e && python e2e.py` |

What the end-to-end test actually proves:
- Both browsers derive the **same SAS** and exchange chat both ways, with a sealed delivery ack.
- A WebRTC call reaches `active` and **audio flows both ways** with signaling sent only as ciphertext.
- Every WebSocket frame seen by the relay was inspected: **no chat plaintext, no SDP, no ICE content**. Only `{type, seq, ct}` envelopes.
- LEAVE ends the session on the peer, clears messages and SAS from the DOM, and the destroyed room code **cannot be reopened**.
- All of it runs under a strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, no inline scripts).

Crypto unit tests cover: MITM relaying with its own keys (SAS mismatch), forged reveal vs. commit, low-order public key, tampered ciphertext (state not advanced), replay, stale/reordered, far-ahead seq, reflection, third-party decryption, padding buckets, oversize, and key destruction.

## NOT verified (be skeptical here)

- **TURN / relay-only mode.** No Docker daemon or coturn in the sandbox. The e2e media path was `host ↔ host` on loopback, which says nothing about NAT traversal or relays. **Test T3 is the first real test of this.**
- **iOS Safari and Android Chrome.** Only desktop Chrome was run. Everything mobile is in the test plan below.
- **Network changes.** The spike has no reconnect or ICE restart by design; it only measures how fast failure is detected.
- **The crypto construction has not been reviewed.** It uses only libsodium primitives (X25519, BLAKE2b, XChaCha20-Poly1305) but composes them into a *custom protocol*. Treat it as a spike. Before production, replace it with a reviewed implementation (e.g. a Noise library) or get an independent review. Claims are limited to: confidentiality/integrity, forward secrecy, replay rejection, and peer authentication **only after** the SAS is compared. No post-compromise security.

## Run it

```bash
# one-time
cd client && npm install && npm run build         # outputs client/dist
cd ../server && pip install -r requirements.txt

# run (serves the built client + relay on one origin)
cd server && uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` on your computer. `localhost` counts as a secure context, so the microphone works.

**Phones need HTTPS** (`getUserMedia` is blocked on plain HTTP). Simplest: a tunnel, one origin covers page + WebSocket:

```bash
cloudflared tunnel --url http://localhost:8000     # or: ngrok http 8000
```

Open the printed `https://…` URL on both devices. One taps **Create room**, sends the link; the other opens it and taps **Join**.

### Optional: TURN (needed for T3)

Needs a host with a public IP, UDP 3478 + TCP 5349 (forward 443→5349 for TURNS-on-443) and a TLS cert in `coturn/certs/`.

```bash
cd coturn
TURN_SECRET=$(openssl rand -hex 32) TURN_REALM=turn.example.com TURN_EXTERNAL_IP=<public-ip> docker compose up -d
# then start the relay server with the same secret:
export TURN_SECRET=<same secret>
export TURN_URLS="turns:turn.example.com:443?transport=tcp,turn:turn.example.com:3478?transport=udp"
uvicorn main:app --host 0.0.0.0 --port 8000
```

With TURN configured, **auto** policy becomes relay-only. Use the *ICE policy* dropdown on each device to override.

## Device test plan

Use the **Diagnostics** panel on each device. After each test tap **Copy log** and paste it somewhere you can send back, along with the device/OS/browser version. The log contains no keys, SDP, ciphertext or message text.

Before starting: confirm the app loads, SAS matches on both devices, and chat works. If not, stop and send the log.

| # | Test | Steps | Record | Why it matters |
|---|---|---|---|---|
| T1 | Baseline | Desktop Chrome ↔ iPhone Safari, same Wi-Fi, policy **all**. Chat, compare SAS, call 1 min. | Works? Any `remote audio play() blocked` log? | Core flow on iOS |
| T2 | Cross-network, no TURN | Phone on cellular ↔ laptop on Wi-Fi, policy **all**, no TURN configured. Call. | Connected? Media path (host/srflx/relay)? Time to connect | Shows whether TURN is truly required (spec 6) |
| T3 | TURN relay-only | TURN configured, policy **relay**, both on different networks. Call. | Path must show `relay`. Audio flows? RTT? Also try a restrictive network (guest/corporate Wi-Fi) with TURNS-443 | Validates D8 and the coturn config |
| T4 | iOS background, chat only | Active session. Switch app / lock screen for 10 s, 30 s, 60 s, 5 min. Return each time. | Did the socket survive? `TIMER GAP`, `visibilitychange`, `socket closed code=` lines | Sets the disconnect grace default (D6); decides if iOS is viable |
| T5 | iOS background, in call | Active call. Switch app for 10 s / 30 s; separately lock screen. | Does audio continue both ways? Does mic capture stop? Recovery on return? | Voice is the most fragile on iOS |
| T6 | Wake Lock | Tick *Keep screen awake*; repeat T4/T5 with screen idle (no lock). | Held vs. released; does it change T4/T5 results? | Cheap mitigation candidate |
| T7 | Android background | Repeat T4 and T5 on Android Chrome. | Same | Compare with iOS |
| T8 | Network flap | During chat then during a call: toggle airplane mode 5 s; switch Wi-Fi → cellular. | Seconds until `socket closed`; ICE state transitions | Reconnect + ICE-restart design (Phase 3/4) |
| T9 | Reload | Reload one tab mid-session. | How fast does the peer see "ended"? | Confirms D5 (reload = session over) |
| T10 | Low-end device | Oldest/slowest phone you have: cold load on cellular. | Seconds to usable; any jank during call | Bundle is 248 kB gzip because libsodium embeds WASM |
| T11 | Mismatch path | Tamper is hard to do by hand; instead tap **Does not match** on one side. | Both sides end, nothing remains | UX of the failure path |

### How results change the design

| If you see… | Then… |
|---|---|
| iOS Safari drops the socket or suspends within ~10–30 s of backgrounding | Document "keep the app in the foreground"; set grace ≥ 60 s with a clear UI warning; evaluate PWA/native wrapper for iOS. D6 default confirmed or raised |
| Calls die on app switch on iOS regardless of Wake Lock | Voice on iOS web is "foreground only." Say so in the UI, or plan a native client later |
| T2 fails without TURN | Confirms TURN is mandatory, not optional |
| T3 shows `relay` and audio flows | D8 (relay-only default) is practical; measure added latency |
| T3 path shows `host`/`srflx` despite relay policy | Config bug. Fix before Phase 4 |
| T10 load is slow | Compare `@noble/*` (smaller, audited, pure JS) with libsodium in Phase 3 |

## Findings from building the spike (already relevant to the design)

1. **`libsodium-wrappers@0.7.16` ships a broken ESM entry** (imports `./libsodium.mjs`, which lives in the sibling `libsodium` package). `vite.config.ts` aliases to the package's CJS entry. Pin and re-check on upgrades.
2. **CSP needs `'wasm-unsafe-eval'`** for libsodium's WASM. It permits compiling WebAssembly only, not JavaScript `eval`. Everything else in the CSP stays strict (no inline scripts, `default-src 'self'`).
3. **Bundle size:** 727 kB raw / 248 kB gzip, nearly all libsodium. Relevant to the low-end-device requirement. See T10.
4. **Signaling is sealed:** SDP offers/answers and ICE candidates travel inside the E2EE channel, so a malicious relay cannot swap DTLS fingerprints without breaking the SAS-authenticated session. The e2e test asserts the relay sees no `a=fingerprint`, `v=0`, `candidate:` etc.
5. **Room-code probing:** unknown, expired and full rooms return the same close code (4409), consistent with the anti-enumeration design.
6. **Frame budget:** the largest relayed frame in the e2e run was ~5.5 KB (the SDP offer, in the 4 KB padding bucket after base64). The server caps frames at 64 KB and sealed messages at 16 KB.

## Spike-only shortcuts (do not carry into Phase 2)

Room codes instead of PINs · no Redis or persistence · no identity/session tokens or rotation · no reconnect or message queue · per-socket rate limit only · no PoW · `unsafe-inline` styles · TURN secret on the command line · no logging policy beyond "don't log secrets".
