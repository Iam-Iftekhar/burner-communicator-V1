"""End-to-end spike test: two real Chrome instances, real WebRTC, fake microphones.

Verifies (against the built client + relay server):
  1. pairing + commit-reveal handshake, identical SAS on both sides
  2. encrypted chat both directions + in-channel delivery ack
  3. a WebRTC voice call whose SDP/ICE is sent only as ciphertext, with audio actually flowing
  4. the relay NEVER sees plaintext chat text or any SDP/ICE content (inspects every WS frame)
  5. LEAVE destroys the session for both sides and the room code cannot be reopened
"""
import json, os, subprocess, sys, time
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"

env = dict(os.environ, STATIC_DIR=str(ROOT / "client" / "dist"))
for k in ("TURN_URLS", "TURN_SECRET", "STUN_URLS"):
    env.pop(k, None)
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(PORT), "--log-level", "warning"],
                       cwd=ROOT / "server", env=env)
results = []
def wait_until(fn, timeout=15.0, what=""):
    """Eval-free polling: the page's strict CSP (no unsafe-eval) stays enforced during the test."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn(): return
        except Exception:
            pass
        time.sleep(0.2)
    raise TimeoutError(what or "condition not met")
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)

try:
    for _ in range(50):
        try:
            import urllib.request
            urllib.request.urlopen(BASE + "/healthz", timeout=1).read(); break
        except Exception:
            time.sleep(0.2)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path="/usr/bin/google-chrome", headless=True,
            args=["--no-sandbox", "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream",
                  "--disable-features=WebRtcHideLocalIpsWithMdns", "--autoplay-policy=no-user-gesture-required"])
        ctxA, ctxB = browser.new_context(), browser.new_context()
        ctxA.grant_permissions(["microphone"], origin=BASE); ctxB.grant_permissions(["microphone"], origin=BASE)
        A, B = ctxA.new_page(), ctxB.new_page()
        frames = []   # every raw frame the relay saw, both directions, both clients
        for page in (A, B):
            def hook(ws):
                ws.on("framesent", lambda f: frames.append(f if isinstance(f, str) else f.decode("utf-8", "ignore")))
                ws.on("framereceived", lambda f: frames.append(f if isinstance(f, str) else f.decode("utf-8", "ignore")))
            page.on("websocket", hook)
        errors = []
        for name, page in (("A", A), ("B", B)):
            page.on("pageerror", lambda e, n=name: errors.append(f"{n}: {e}"))

        A.goto(BASE); A.click("#btn-create")
        wait_until(lambda: "#room=" in A.input_value("#share-link"), 10, "share link")
        link = A.input_value("#share-link")
        room = link.split("#room=")[1]
        B.goto(link); B.click("#btn-join")

        wait_until(lambda: A.inner_text("#sas").strip() != "--- ---", 15, "SAS on A")
        wait_until(lambda: B.inner_text("#sas").strip() != "--- ---", 15, "SAS on B")
        sasA, sasB = A.inner_text("#sas"), B.inner_text("#sas")
        check("handshake completes; both sides show identical SAS", sasA == sasB and len(sasA) == 7, sasA)
        A.click("#btn-sas-ok"); B.click("#btn-sas-ok")

        SECRET_A, SECRET_B = "meet-at-the-old-bridge-0042", "bring-the-blue-folder-7731"
        A.fill("#chat-input", SECRET_A); A.click("#btn-send")
        wait_until(lambda: SECRET_A in B.inner_text("#messages"), 10, "msg A->B")
        B.fill("#chat-input", SECRET_B); B.click("#btn-send")
        wait_until(lambda: SECRET_B in A.inner_text("#messages"), 10, "msg B->A")
        check("chat delivered in both directions", True)
        wait_until(lambda: "✓" in A.locator("#messages li.me small").first.inner_text(), 10, "ack")
        check("delivery ack (sealed, peer-originated) shown on sender", True)

        A.click("#btn-call")
        B.wait_for_selector("#incoming:not(.hidden)", timeout=10000); B.click("#btn-accept")
        wait_until(lambda: A.inner_text("#call-status").startswith("active"), 30, "call active on A")
        wait_until(lambda: B.inner_text("#call-status").startswith("active"), 30, "call active on B")
        check("WebRTC call reaches 'active' on both sides (SDP/ICE via sealed signaling)", True)
        time.sleep(5)
        audioA, audioB, path = A.inner_text("#d-audio"), B.inner_text("#d-audio"), A.inner_text("#d-path")
        check("audio flowing A<-B and B<-A", audioA.startswith("flowing") and audioB.startswith("flowing"), f"{audioA} | {audioB}")
        print("      media path:", path)
        A.click("#btn-mute"); time.sleep(0.3)
        check("mute toggles", A.inner_text("#btn-mute") == "Unmute")
        B.click("#btn-hangup")
        wait_until(lambda: A.inner_text("#call-status") == "no call", 10, "hangup on A")
        check("hang up ends call on both sides", B.inner_text("#call-status") == "no call")

        # ---- what did the relay see? ----
        blob = "\n".join(frames)
        check("relay saw >0 frames", len(frames) > 10, f"{len(frames)} frames")
        biggest = max(len(f) for f in frames)
        check("largest relayed frame is far below the 64 KB server cap", biggest < 20000, f"{biggest} bytes")
        check("relay never saw chat plaintext", SECRET_A not in blob and SECRET_B not in blob)
        check("relay never saw SDP or ICE content",
              all(tok not in blob for tok in ("a=fingerprint", "v=0", "candidate:", "a=ice-ufrag", "m=audio")))
        types = {json.loads(f).get("type") for f in frames if f.startswith("{")}
        check("only opaque envelope types on the wire", types <= {"join", "joined", "peer_joined", "hs", "msg", "sig", "ping", "pong", "leave", "ended"}, str(sorted(t for t in types if t)))
        sig_frames = [json.loads(f) for f in frames if f.startswith("{") and json.loads(f).get("type") in ("msg", "sig")]
        check("msg/sig frames carry only {type, seq, ct}", all(set(x) == {"type", "seq", "ct"} for x in sig_frames))

        # ---- LEAVE ----
        A.click("#btn-leave")
        B.wait_for_selector("#screen-ended:not(.hidden)", timeout=10000)
        check("LEAVE on A ends the session on B", True)
        check("ended screen on A", not A.is_hidden("#screen-ended"))
        check("B's message list is cleared", B.inner_html("#messages") == "")
        check("A's message list is cleared", A.inner_html("#messages") == "")
        check("SAS cleared from DOM", B.inner_text("#sas").strip() == "--- ---")
        ctxC = browser.new_context(); C = ctxC.new_page()
        C.goto(f"{BASE}/#room={room}"); C.click("#btn-join")
        C.wait_for_selector("#screen-ended:not(.hidden)", timeout=10000)
        check("destroyed room cannot be reopened", "unavailable" in C.inner_text("#ended-reason").lower(), C.inner_text("#ended-reason"))
        check("no page errors", not errors, "; ".join(errors))
        browser.close()
finally:
    srv.terminate()
    try: srv.wait(5)
    except Exception: srv.kill()

failed = [r for r in results if not r[1]]
print(f"\n{len(results)-len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
