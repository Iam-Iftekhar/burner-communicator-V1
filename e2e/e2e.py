"""End-to-end test: two independent real Chrome profiles (separate cookie jars = two users), real WebRTC.

Covers the PIN-identity feature end to end:
  identity   : each browser gets a different 4-digit PIN; PIN survives reload AND a server restart;
               recovery credential is an HttpOnly SameSite=Strict cookie that page JS cannot read
  requests   : input validation, unavailable recipient, reject, accept, incoming modal shows sender PIN
  session    : same SAS on both sides; chat/call locked until BOTH confirm the SAS
  e2ee       : chat + sealed acks, WebRTC voice with sealed SDP/ICE, relay never sees plaintext/SDP/ICE
  teardown   : LEAVE ends both sides, PINs persist, SAS mismatch ends the session
"""
import json, os, re, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
DB = os.path.join(tempfile.mkdtemp(prefix="eph-e2e-"), "identities.db")

results = []
srv = None

def start_server():
    global srv
    env = dict(os.environ, STATIC_DIR=str(ROOT / "client" / "dist"), EPHEMERAL_DB=DB, REJECT_COOLDOWN_S="1")
    for k in ("TURN_URLS", "TURN_SECRET", "STUN_URLS", "TRUST_PROXY", "ALLOWED_ORIGINS"):
        env.pop(k, None)
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(PORT), "--log-level", "warning"],
                           cwd=ROOT / "server", env=env)
    for _ in range(100):
        try:
            urllib.request.urlopen(BASE + "/healthz", timeout=1).read(); return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("server did not start")

def stop_server():
    global srv
    if srv:
        srv.terminate()
        try: srv.wait(5)
        except Exception: srv.kill()
        srv = None

def wait_until(fn, timeout=15.0, what=""):
    """Eval-free polling: the page's strict CSP (no unsafe-eval) stays enforced during the test."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn(): return
        except Exception:
            pass
        time.sleep(0.15)
    raise TimeoutError(what or "condition not met")

def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)

try:
    start_server()
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path="/usr/bin/google-chrome", headless=True,
            args=["--no-sandbox", "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream",
                  "--disable-features=WebRtcHideLocalIpsWithMdns", "--autoplay-policy=no-user-gesture-required"])
        ctxA, ctxB = browser.new_context(), browser.new_context()
        ctxA.grant_permissions(["microphone"], origin=BASE); ctxB.grant_permissions(["microphone"], origin=BASE)
        A, B = ctxA.new_page(), ctxB.new_page()
        frames = []
        for page in (A, B):
            def hook(ws):
                ws.on("framesent", lambda f: frames.append(f if isinstance(f, str) else f.decode("utf-8", "ignore")))
                ws.on("framereceived", lambda f: frames.append(f if isinstance(f, str) else f.decode("utf-8", "ignore")))
            page.on("websocket", hook)
        errors = []
        for name, page in (("A", A), ("B", B)):
            page.on("pageerror", lambda e, n=name: errors.append(f"{n}: {e}"))

        pin = lambda pg: pg.inner_text("#my-pin").strip()
        state = lambda pg: pg.inner_text("#conn-state").strip()
        vis = lambda pg, sel: pg.is_visible(sel)
        def has_pin(pg): return re.fullmatch(r"\d{4}", pin(pg)) is not None
        def online(pg): return has_pin(pg) and state(pg) == "Online"

        # ---------------- identity ----------------
        A.goto(BASE); B.goto(BASE)
        wait_until(lambda: online(A) and online(B), 15, "both online")
        pinA, pinB = pin(A), pin(B)
        check("each browser is automatically assigned a 4-digit PIN", True, f"{pinA} / {pinB}")
        check("the two users have different PINs", pinA != pinB)

        ck = {c["name"]: c for c in ctxA.cookies()}.get("eph_id")
        check("recovery credential is an HttpOnly + SameSite=Strict cookie",
              bool(ck) and ck["httpOnly"] and ck["sameSite"] == "Strict", str({k: ck[k] for k in ("httpOnly", "sameSite", "secure")}) if ck else "missing")
        try:
            jscookie = A.evaluate("() => document.cookie")
            check("page JavaScript cannot read the credential", "eph_id" not in jscookie, repr(jscookie))
            storage = A.evaluate("() => JSON.stringify([Object.keys(localStorage), Object.keys(sessionStorage)])")
            check("nothing is written to localStorage/sessionStorage", storage == "[[],[]]", storage)
        except Exception as e:
            check("page JavaScript cannot read the credential", False, f"evaluate failed: {e}")

        A.reload()
        wait_until(lambda: online(A), 15, "A back online after reload")
        check("refreshing does NOT generate a new PIN", pin(A) == pinA, pin(A))

        # ---------------- server restart: identities must survive ----------------
        stop_server(); start_server()
        wait_until(lambda: online(A) and online(B), 30, "auto-reconnect after server restart")
        check("clients auto-reconnect after a server restart", True)
        check("PINs unchanged after server restart (no re-registration)", pin(A) == pinA and pin(B) == pinB, f"{pin(A)} / {pin(B)}")
        A.reload(); wait_until(lambda: online(A), 15)
        check("PIN still the same after restart + reload", pin(A) == pinA)

        # ---------------- input validation ----------------
        A.fill("#peer-pin", "ab12cd")
        check("non-digits are stripped from the PIN field", A.input_value("#peer-pin") == "12", A.input_value("#peer-pin"))
        check("validation message shown for <4 digits", "exactly 4" in A.inner_text("#peer-pin-msg"))
        check("Connect disabled until 4 digits", A.is_disabled("#btn-connect"))
        A.fill("#peer-pin", pinA); A.click("#btn-connect")
        check("own PIN is refused client-side", "own PIN" in A.inner_text("#peer-pin-msg"))

        # ---------------- unavailable recipient (also proves leading zeros survive the round trip) ----------------
        unused = next(x for x in ("0000", "0001", "0002") if x not in (pinA, pinB))
        A.fill("#peer-pin", unused); A.click("#btn-connect")
        wait_until(lambda: "Recipient unavailable" in A.inner_text("#peer-pin-msg"), 10, "unavailable")
        check("unknown/offline PIN -> 'Recipient unavailable' (leading zeros kept)", True, unused)

        # ---------------- reject ----------------
        A.fill("#peer-pin", pinB); A.click("#btn-connect")
        wait_until(lambda: vis(B, "#incoming-modal"), 10, "incoming modal")
        who = B.inner_text("#incoming-list .who").strip()
        check("recipient sees an incoming request showing the sender's PIN", who == pinA, who)
        wait_until(lambda: "Waiting for acceptance" in state(A), 5, "waiting state")
        check("sender sees 'Waiting for acceptance'", True)
        B.click("#incoming-list button.danger")
        wait_until(lambda: "Request rejected" in A.inner_text("#peer-pin-msg"), 10, "rejected")
        check("reject -> sender notified, no session created", not vis(A, "#screen-session") and not vis(B, "#screen-session"))
        check("incoming modal closes after reject", not vis(B, "#incoming-modal"))
        time.sleep(1.3)  # REJECT_COOLDOWN_S=1

        # ---------------- accept -> session ----------------
        A.fill("#peer-pin", pinB); A.click("#btn-connect")
        wait_until(lambda: vis(B, "#incoming-modal"), 10)
        B.click("#incoming-list button.primary")
        wait_until(lambda: vis(A, "#screen-session") and vis(B, "#screen-session"), 15, "session screens")
        check("accept establishes a session for both users", True)
        check("each side shows the other's PIN", pinB in A.inner_text("#peer-label") and pinA in B.inner_text("#peer-label"))
        no_sas = lambda pg: pg.inner_text("#sas").strip() == "--- ---"
        wait_until(lambda: not no_sas(A) and not no_sas(B), 15, "SAS")
        sasA, sasB = A.inner_text("#sas"), B.inner_text("#sas")
        check("E2EE handshake succeeds; both derive the same SAS", sasA == sasB and len(sasA) == 7, sasA)
        check("status shows 'Comparing SAS'", "Comparing SAS" in A.inner_text("#status"))

        # ---------------- SAS gating ----------------
        check("chat and call locked before SAS verification", A.is_disabled("#chat-input") and B.is_disabled("#chat-input") and A.is_disabled("#btn-call"))
        A.click("#btn-sas-ok")
        wait_until(lambda: "Waiting for the other person" in A.inner_text("#verify-banner"), 5)
        time.sleep(0.5)
        check("one-sided confirmation does NOT unlock chat on either side", A.is_disabled("#chat-input") and B.is_disabled("#chat-input"))
        B.click("#btn-sas-ok")
        wait_until(lambda: not A.is_disabled("#chat-input") and not B.is_disabled("#chat-input"), 10, "unlock")
        check("chat unlocks only after BOTH sides confirm", True)
        check("status shows 'Secure session established'", "Secure session established" in A.inner_text("#status"))

        # ---------------- encrypted chat ----------------
        SECRET_A, SECRET_B = "meet-at-the-old-bridge-0042", "bring-the-blue-folder-7731"
        A.fill("#chat-input", SECRET_A); A.click("#btn-send")
        wait_until(lambda: SECRET_A in B.inner_text("#messages"), 10, "msg A->B")
        B.fill("#chat-input", SECRET_B); B.click("#btn-send")
        wait_until(lambda: SECRET_B in A.inner_text("#messages"), 10, "msg B->A")
        check("encrypted chat works in both directions", True)
        wait_until(lambda: "✓" in A.locator("#messages li.me small").first.inner_text(), 10, "ack")
        check("sealed delivery acknowledgment shown", True)

        # ---------------- voice ----------------
        A.click("#btn-call")
        wait_until(lambda: vis(B, "#incoming"), 10); B.click("#btn-accept")
        wait_until(lambda: A.inner_text("#call-status").startswith("active"), 30, "call A")
        wait_until(lambda: B.inner_text("#call-status").startswith("active"), 30, "call B")
        check("WebRTC call reaches 'active' (SDP/ICE sealed)", True)
        time.sleep(5)
        audioA, audioB = A.inner_text("#d-audio"), B.inner_text("#d-audio")
        check("audio flowing both ways", audioA.startswith("flowing") and audioB.startswith("flowing"), f"{audioA} | {audioB}")
        print("      media path:", A.inner_text("#d-path"))
        A.click("#btn-mute"); time.sleep(0.3)
        check("mute toggles", A.inner_text("#btn-mute") == "Unmute")
        B.click("#btn-hangup")
        wait_until(lambda: A.inner_text("#call-status") == "no call", 10)
        check("hang up ends call on both sides", B.inner_text("#call-status") == "no call")

        # ---------------- LEAVE ----------------
        A.click("#btn-leave")
        wait_until(lambda: vis(B, "#screen-ended"), 10, "B ended")
        check("LEAVE on A ends the session on B", True, B.inner_text("#ended-reason"))
        check("ended screen on A", vis(A, "#screen-ended"))
        check("message lists and SAS cleared", A.inner_html("#messages") == "" and B.inner_html("#messages") == "" and no_sas(A) and no_sas(B))
        A.click("#btn-home"); B.click("#btn-home")
        wait_until(lambda: online(A) and online(B), 10, "back online")
        check("after LEAVE both stay online with the SAME PINs", pin(A) == pinA and pin(B) == pinB)

        # ---------------- SAS mismatch terminates the session ----------------
        A.fill("#peer-pin", pinB); A.click("#btn-connect")
        wait_until(lambda: vis(B, "#incoming-modal"), 10); B.click("#incoming-list button.primary")
        wait_until(lambda: not no_sas(A) and not no_sas(B), 15, "SAS 2")
        newsas = A.inner_text("#sas")
        check("a new session derives a fresh SAS", newsas != sasA, f"{sasA} -> {newsas}")
        A.click("#btn-sas-bad")
        wait_until(lambda: vis(B, "#screen-ended") and vis(A, "#screen-ended"), 10, "mismatch end")
        check("SAS mismatch terminates the session for both", "did not match" in A.inner_text("#ended-reason"), A.inner_text("#ended-reason"))

        # ---------------- what did the relay see? ----------------
        blob = "\n".join(frames)
        types = set()
        for f in frames:
            if f.startswith("{"):
                try: types.add(json.loads(f).get("type"))
                except Exception: pass
        check("relay saw traffic", len(frames) > 30, f"{len(frames)} frames")
        check("relay never saw chat plaintext", SECRET_A not in blob and SECRET_B not in blob)
        check("relay never saw SDP or ICE content", all(t not in blob for t in ("a=fingerprint", "v=0", "candidate:", "a=ice-ufrag", "m=audio")))
        allowed = {"authed", "incoming", "incoming_closed", "request_update", "session", "hs", "msg", "sig", "ping", "pong", "ended",
                   "error", "connect", "accept", "reject", "cancel", "leave", "replaced", "auth_failed"}
        check("only expected envelope types on the wire", types <= allowed, str(sorted(types - allowed)))
        opaque = [json.loads(f) for f in frames if f.startswith("{") and json.loads(f).get("type") in ("msg", "sig")]
        check("msg/sig frames carry only {type, seq, ct}", bool(opaque) and all(set(x) == {"type", "seq", "ct"} for x in opaque))
        tok = ck["value"] if ck else "no-cookie"
        check("recovery credential never appears on the WebSocket", tok not in blob)
        check("largest relayed frame is far below the 64 KB cap", max(len(f) for f in frames) < 20000, f"{max(len(f) for f in frames)} bytes")
        check("no page errors", not errors, "; ".join(errors))

        # ---------------- full browser restart (persistent profile on disk) ----------------
        udir = tempfile.mkdtemp(prefix="eph-profile-")
        launch = dict(executable_path="/usr/bin/google-chrome", headless=True, args=["--no-sandbox"])
        c1 = p.chromium.launch_persistent_context(udir, **launch)
        pg = c1.new_page(); pg.goto(BASE)
        wait_until(lambda: online(pg), 15, "profile first run")
        pin_first = pin(pg)
        c1.close()  # browser fully closed
        c2 = p.chromium.launch_persistent_context(udir, **launch)
        pg2 = c2.new_page(); pg2.goto(BASE)
        wait_until(lambda: online(pg2), 15, "profile second run")
        check("PIN persists across a full browser restart", pin(pg2) == pin_first, f"{pin_first} -> {pin(pg2)}")
        c2.close()
        browser.close()
finally:
    stop_server()

failed = [r for r in results if not r[1]]
print(f"\n{len(results)-len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
