import "./style.css";
import { E2EESession, type HsMsg, type Role } from "./crypto";

// ---------- tiny DOM helpers ----------
const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
};
const show = (el: HTMLElement, on: boolean) => el.classList.toggle("hidden", !on);

// ---------- diagnostics log (never logs keys, SDP, ciphertext or message bodies) ----------
const t0 = performance.now();
const logLines: string[] = [];
function log(msg: string) {
  const line = `[${((performance.now() - t0) / 1000).toFixed(1)}s ${new Date().toISOString().slice(11, 19)}Z] ${msg}`;
  logLines.push(line);
  if (logLines.length > 400) logLines.shift();
  const el = $("log");
  el.textContent = logLines.slice(-150).join("\n");
  el.scrollTop = el.scrollHeight;
}
const setDiag = (id: string, v: string) => ($(id).textContent = v);

// ---------- session state (memory only: nothing is written to any browser storage) ----------
type CallState = "idle" | "inviting" | "ringing" | "connecting" | "active";
let ws: WebSocket | null = null;
let sess: E2EESession | null = null;
let role: Role | null = null;
let verified: boolean | null = null;
let ended = false;
let frameQueue: Promise<void> = Promise.resolve();

let pc: RTCPeerConnection | null = null;
let localStream: MediaStream | null = null;
let callState: CallState = "idle";
let pendingIce: RTCIceCandidateInit[] = [];
let remoteDescSet = false;
let muted = false;

let pingTimer: number | undefined;
let statsTimer: number | undefined;
let lastPongAt = 0;
let lastTick = performance.now();
let lastPath = "";
let lastAudioBytes = 0;
let wakeLock: WakeLockSentinel | null = null;

// ---------- screens ----------
function screen(name: "setup" | "session" | "ended") {
  show($("screen-setup"), name === "setup");
  show($("screen-session"), name === "session");
  show($("screen-ended"), name === "ended");
}
const setStatus = (s: string) => ($("status").textContent = s);

// ---------- wire helpers ----------
function sendRaw(obj: Record<string, unknown>) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function sendSecure(type: "msg" | "sig", payload: unknown) {
  if (!sess || !sess.established) return;
  const { seq, ct } = sess.seal(payload);
  sendRaw({ type, seq, ct });
}

// ---------- connect / join ----------
async function createRoom() {
  const r = await fetch("/room", { method: "POST" });
  const { room } = (await r.json()) as { room: string };
  $<HTMLInputElement>("share-link").value = `${location.origin}/#room=${room}`;
  show($("share"), true);
  log("room created; joining as first participant");
  connect(room);
}

function connect(room: string) {
  ended = false;
  verified = null;
  screen("session");
  setStatus("connecting…");
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws`);
  setDiag("d-ws", "connecting");
  ws.onopen = () => {
    setDiag("d-ws", "open");
    log("socket open");
    // The room code travels in the first frame, never in the URL.
    sendRaw({ type: "join", room });
    startHeartbeat();
  };
  ws.onmessage = (ev) => {
    frameQueue = frameQueue.then(() => onFrame(ev.data as string)).catch((e) => log(`frame error: ${(e as Error).message}`));
  };
  ws.onclose = (ev) => {
    setDiag("d-ws", `closed (code ${ev.code})`);
    log(`socket closed code=${ev.code} clean=${ev.wasClean} visibility=${document.visibilityState}`);
    if (!ended) finish(ev.code === 4409 ? "Room unavailable (unknown, expired or full)." : "Connection lost. The session cannot be resumed.");
  };
  ws.onerror = () => log("socket error");
}

async function onFrame(text: string) {
  let f: { type?: string; [k: string]: unknown };
  try {
    f = JSON.parse(text);
  } catch {
    return;
  }
  switch (f.type) {
    case "joined": {
      role = f.role === "a" || f.role === "b" ? f.role : null;
      if (!role) return finish("Protocol error.");
      sess = await E2EESession.create(role);
      if (role === "b") sess.start();
      setStatus(role === "a" ? "waiting for the other device…" : "joined, waiting for handshake…");
      log(`joined as ${role}`);
      break;
    }
    case "peer_joined": {
      log("peer joined");
      if (role === "a" && sess) {
        const m = sess.start();
        if (m) sendRaw({ type: "hs", ...m });
      }
      break;
    }
    case "hs": {
      if (!sess) return;
      try {
        const reply = sess.handleHandshake(f as unknown as HsMsg);
        if (reply) sendRaw({ type: "hs", ...reply });
        if (sess.established) onEstablished();
      } catch (e) {
        log(`handshake failed: ${(e as Error).message}`);
        leave("Handshake failed.");
      }
      break;
    }
    case "msg":
    case "sig": {
      if (!sess || typeof f.seq !== "number" || typeof f.ct !== "string") return;
      let payload: Record<string, unknown>;
      try {
        payload = sess.open<Record<string, unknown>>(f.seq, f.ct);
      } catch (e) {
        log(`dropped bad frame (${f.type}): ${(e as Error).message}`);
        return;
      }
      if (f.type === "msg") onChatPayload(payload);
      else await onSignalPayload(payload);
      break;
    }
    case "pong": {
      lastPongAt = performance.now();
      if (typeof f.t === "number") setDiag("d-rtt", `${Math.round(performance.now() - f.t)} ms`);
      break;
    }
    case "ended":
      finish("The other side left, or the session expired.");
      break;
  }
}

function onEstablished() {
  if (!sess) return;
  $("sas").textContent = sess.sas;
  show($("sas-box"), true);
  show($("verify-banner"), true);
  setStatus("encrypted (not verified)");
  $<HTMLInputElement>("chat-input").disabled = false;
  $<HTMLButtonElement>("btn-send").disabled = false;
  $<HTMLButtonElement>("btn-call").disabled = false;
  log("key agreement complete; sending key-confirmation");
  sendSecure("msg", { t: "hello" });
}

// ---------- chat ----------
const myMsgs = new Map<string, HTMLLIElement>();

function addMessage(body: string, mine: boolean, id?: string) {
  const li = document.createElement("li");
  li.className = mine ? "me" : "";
  li.textContent = body; // textContent only, never innerHTML
  const small = document.createElement("small");
  small.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  li.appendChild(small);
  $("messages").appendChild(li);
  $("messages").scrollTop = $("messages").scrollHeight;
  if (mine && id) myMsgs.set(id, li);
}

function onChatPayload(p: Record<string, unknown>) {
  if (p.t === "hello") {
    log("peer key-confirmation received (both directions decrypt)");
    return;
  }
  if (p.t === "chat" && typeof p.body === "string" && typeof p.id === "string") {
    addMessage(p.body, false);
    sendSecure("msg", { t: "ack", id: p.id }); // delivery receipt is inside the E2EE channel
  } else if (p.t === "ack" && typeof p.id === "string") {
    const li = myMsgs.get(p.id);
    if (li) li.querySelector("small")!.textContent += " ✓";
  }
}

// ---------- calls: all signaling is sealed, so the server only relays ciphertext ----------
function setCall(s: CallState, extra = "") {
  callState = s;
  $("call-status").textContent = s === "idle" ? "no call" : `${s}${extra ? " – " + extra : ""}`;
  $<HTMLButtonElement>("btn-call").disabled = s !== "idle" || !sess?.established;
  $<HTMLButtonElement>("btn-hangup").disabled = s === "idle";
  $<HTMLButtonElement>("btn-mute").disabled = s !== "active" && s !== "connecting";
  show($("incoming"), s === "ringing");
}

async function getMic(): Promise<boolean> {
  if (localStream) return true;
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: false });
    log("microphone granted");
    return true;
  } catch (e) {
    log(`microphone failed: ${(e as Error).name}`);
    setCall("idle", "microphone unavailable");
    return false;
  }
}

async function iceConfig(): Promise<RTCConfiguration> {
  const policy = $<HTMLSelectElement>("ice-policy").value;
  const r = await fetch(`/ice${policy ? `?policy=${policy}` : ""}`);
  const c = (await r.json()) as { iceServers: RTCIceServer[]; iceTransportPolicy: RTCIceTransportPolicy; turnConfigured: boolean };
  log(`ICE policy=${c.iceTransportPolicy} turnConfigured=${c.turnConfigured} servers=${c.iceServers.length}`);
  return { iceServers: c.iceServers, iceTransportPolicy: c.iceTransportPolicy };
}

async function newPeerConnection() {
  closePc();
  pc = new RTCPeerConnection(await iceConfig());
  remoteDescSet = false;
  pendingIce = [];
  pc.onicecandidate = (e) => {
    if (e.candidate) sendSecure("sig", { t: "ice", cand: e.candidate.toJSON() });
  };
  pc.ontrack = (e) => {
    const a = $<HTMLAudioElement>("remote-audio");
    a.srcObject = e.streams[0] ?? new MediaStream([e.track]);
    a.play().catch((err) => log(`remote audio play() blocked: ${(err as Error).name}`));
  };
  pc.oniceconnectionstatechange = () => {
    log(`iceConnectionState=${pc?.iceConnectionState}`);
    updateIceDiag();
  };
  pc.onconnectionstatechange = () => {
    log(`connectionState=${pc?.connectionState}`);
    updateIceDiag();
    if (pc?.connectionState === "connected") {
      setCall("active");
      startStats();
    } else if (pc?.connectionState === "failed") {
      log("call failed");
      endCall(true);
    }
  };
  for (const t of localStream?.getTracks() ?? []) pc.addTrack(t, localStream!);
}

function updateIceDiag() {
  setDiag("d-ice", pc ? `${pc.iceConnectionState} / ${pc.connectionState}` : "-");
}

async function startCall() {
  if (callState !== "idle" || !sess?.established) return;
  if (!(await getMic())) return;
  setCall("inviting");
  sendSecure("sig", { t: "call", op: "invite" });
}

async function acceptCall() {
  if (callState !== "ringing") return;
  if (!(await getMic())) {
    sendSecure("sig", { t: "call", op: "reject" });
    return;
  }
  await newPeerConnection();
  setCall("connecting");
  sendSecure("sig", { t: "call", op: "accept" });
}

function rejectCall() {
  sendSecure("sig", { t: "call", op: "reject" });
  setCall("idle");
}

async function onSignalPayload(p: Record<string, unknown>) {
  if (p.t === "call") {
    if (p.op === "invite" && callState === "idle") {
      setCall("ringing");
    } else if (p.op === "invite") {
      sendSecure("sig", { t: "call", op: "reject" }); // busy / glare: deterministic, caller with role "a" wins below
    } else if (p.op === "accept" && callState === "inviting") {
      await newPeerConnection();
      setCall("connecting");
      const offer = await pc!.createOffer();
      await pc!.setLocalDescription(offer);
      sendSecure("sig", { t: "sdp", kind: "offer", sdp: offer.sdp });
    } else if (p.op === "reject") {
      log("call rejected by peer");
      endCall(false);
    } else if (p.op === "hangup") {
      log("peer hung up");
      endCall(false);
    }
  } else if (p.t === "sdp" && pc && typeof p.sdp === "string") {
    if (p.kind === "offer") {
      await pc.setRemoteDescription({ type: "offer", sdp: p.sdp });
      remoteDescSet = true;
      await flushIce();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      sendSecure("sig", { t: "sdp", kind: "answer", sdp: answer.sdp });
    } else if (p.kind === "answer") {
      await pc.setRemoteDescription({ type: "answer", sdp: p.sdp });
      remoteDescSet = true;
      await flushIce();
    }
  } else if (p.t === "ice" && p.cand && typeof p.cand === "object") {
    if (pc && remoteDescSet) await pc.addIceCandidate(p.cand as RTCIceCandidateInit).catch((e) => log(`addIceCandidate: ${(e as Error).name}`));
    else pendingIce.push(p.cand as RTCIceCandidateInit);
  }
}

async function flushIce() {
  for (const c of pendingIce.splice(0)) await pc?.addIceCandidate(c).catch(() => undefined);
}

function closePc() {
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = undefined;
  if (pc) {
    pc.onicecandidate = pc.ontrack = pc.oniceconnectionstatechange = pc.onconnectionstatechange = null;
    pc.close();
    pc = null;
  }
  const a = $<HTMLAudioElement>("remote-audio");
  a.srcObject = null;
  lastPath = "";
  lastAudioBytes = 0;
  setDiag("d-path", "-");
  setDiag("d-audio", "-");
  updateIceDiag();
}

function releaseMic() {
  localStream?.getTracks().forEach((t) => t.stop());
  localStream = null;
  muted = false;
  $("btn-mute").textContent = "Mute";
}

function endCall(notifyPeer: boolean) {
  if (notifyPeer && callState !== "idle") sendSecure("sig", { t: "call", op: "hangup" });
  closePc();
  releaseMic();
  setCall("idle");
}

function toggleMute() {
  muted = !muted;
  localStream?.getAudioTracks().forEach((t) => (t.enabled = !muted));
  $("btn-mute").textContent = muted ? "Unmute" : "Mute";
  log(muted ? "muted" : "unmuted");
}

// ---------- stats: which path did media actually take? ----------
function startStats() {
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = window.setInterval(() => void pollStats(), 2000);
  void pollStats();
}

async function pollStats() {
  if (!pc) return;
  const stats = await pc.getStats();
  let pairId: string | undefined;
  stats.forEach((r) => {
    if (r.type === "transport" && r.selectedCandidatePairId) pairId = r.selectedCandidatePairId;
  });
  let pair: Record<string, unknown> | undefined;
  stats.forEach((r) => {
    if (r.type === "candidate-pair" && (r.id === pairId || (!pairId && r.nominated && r.state === "succeeded"))) pair = r;
  });
  if (pair) {
    const lt = (stats.get(pair.localCandidateId as string) as Record<string, string> | undefined)?.candidateType ?? "?";
    const rt = (stats.get(pair.remoteCandidateId as string) as Record<string, string> | undefined)?.candidateType ?? "?";
    const rtt = typeof pair.currentRoundTripTime === "number" ? `${Math.round(pair.currentRoundTripTime * 1000)} ms` : "?";
    const path = `local ${lt} ↔ remote ${rt}`;
    setDiag("d-path", `${path}, rtt ${rtt}`);
    if (path !== lastPath) {
      log(`media path: ${path}${lt === "relay" || rt === "relay" ? " (relayed)" : " (DIRECT: peers can see each other's IP)"}`);
      lastPath = path;
    }
  }
  stats.forEach((r) => {
    if (r.type === "inbound-rtp" && r.kind === "audio") {
      const delta = (r.bytesReceived as number) - lastAudioBytes;
      lastAudioBytes = r.bytesReceived as number;
      setDiag("d-audio", `${delta > 0 ? "flowing" : "SILENT"} (+${delta} B / 2s), lost ${r.packetsLost}, jitter ${(((r.jitter as number) ?? 0) * 1000).toFixed(0)} ms`);
      if (delta <= 0 && callState === "active") log("audio stalled (no bytes in last 2s)");
    }
  });
}

// ---------- heartbeat / background behaviour ----------
function startHeartbeat() {
  clearInterval(pingTimer);
  lastPongAt = performance.now();
  lastTick = performance.now();
  pingTimer = window.setInterval(() => {
    const now = performance.now();
    const drift = now - lastTick;
    lastTick = now;
    if (drift > 8000) log(`TIMER GAP: 5s timer fired after ${(drift / 1000).toFixed(1)}s (tab throttled or suspended; visibility=${document.visibilityState})`);
    if (now - lastPongAt > 12000) log(`no pong for ${((now - lastPongAt) / 1000).toFixed(0)}s`);
    sendRaw({ type: "ping", t: now });
  }, 5000);
}

document.addEventListener("visibilitychange", () => {
  setDiag("d-vis", document.visibilityState);
  log(`visibilitychange → ${document.visibilityState}`);
});
window.addEventListener("pagehide", (e) => log(`pagehide persisted=${(e as PageTransitionEvent).persisted}`));
window.addEventListener("pageshow", (e) => log(`pageshow persisted=${(e as PageTransitionEvent).persisted}`));
document.addEventListener("freeze", () => log("page freeze"));
document.addEventListener("resume", () => log("page resume"));
window.addEventListener("online", () => log("network online"));
window.addEventListener("offline", () => log("network offline"));

async function setWake(on: boolean) {
  try {
    if (on) {
      wakeLock = await navigator.wakeLock.request("screen");
      wakeLock.addEventListener("release", () => {
        setDiag("d-wake", "released");
        log("wake lock released");
      });
      setDiag("d-wake", "held");
      log("wake lock acquired");
    } else {
      await wakeLock?.release();
      wakeLock = null;
      setDiag("d-wake", "off");
    }
  } catch (e) {
    setDiag("d-wake", `unavailable (${(e as Error).name})`);
  }
}

// ---------- leave / destroy ----------
function leave(reason: string) {
  if (ended) return;
  sendRaw({ type: "leave" });
  finish(reason);
}

function finish(reason: string) {
  if (ended) return;
  ended = true;
  clearInterval(pingTimer);
  endCall(false);
  sess?.destroy(); // zeroize key material
  sess = null;
  role = null;
  myMsgs.clear();
  $("messages").replaceChildren();
  $<HTMLInputElement>("chat-input").value = "";
  $("sas").textContent = "--- ---";
  show($("sas-box"), false);
  show($("verify-banner"), false);
  pendingIce = [];
  if (ws) {
    ws.onclose = null;
    try {
      ws.close(1000);
    } catch {
      /* already closed */
    }
    ws = null;
  }
  void setWake(false);
  history.replaceState(null, "", location.pathname);
  $("ended-reason").textContent = reason;
  screen("ended");
  log(`session finished: ${reason}`);
}

// ---------- wiring ----------
$("btn-create").addEventListener("click", () => void createRoom().catch((e) => log(`create failed: ${(e as Error).message}`)));
$("btn-join").addEventListener("click", () => {
  const code = $<HTMLInputElement>("join-code").value.trim().toLowerCase();
  if (code) connect(code);
});
$("btn-leave").addEventListener("click", () => leave("You left. The session was destroyed."));
$("btn-home").addEventListener("click", () => {
  show($("share"), false);
  screen("setup");
});
$("chat-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = $<HTMLInputElement>("chat-input");
  const body = input.value.trim();
  if (!body || !sess?.established) return;
  const id = crypto.randomUUID();
  try {
    sendSecure("msg", { t: "chat", id, ts: Date.now(), body });
    addMessage(body, true, id);
    input.value = "";
  } catch (err) {
    log(`send failed: ${(err as Error).message}`);
  }
});
$("btn-sas-ok").addEventListener("click", () => {
  verified = true;
  show($("sas-box"), false);
  const b = $("verify-banner");
  b.className = "banner ok";
  b.textContent = "Verified: codes matched.";
  setStatus("encrypted (verified)");
  log("SAS confirmed by user");
});
$("btn-sas-bad").addEventListener("click", () => {
  verified = false;
  log("SAS mismatch reported by user: possible interception");
  leave("Codes did not match. The session was destroyed because it may have been intercepted.");
});
$("btn-call").addEventListener("click", () => void startCall());
$("btn-accept").addEventListener("click", () => void acceptCall());
$("btn-reject").addEventListener("click", rejectCall);
$("btn-hangup").addEventListener("click", () => endCall(true));
$("btn-mute").addEventListener("click", toggleMute);
$("wake").addEventListener("change", (e) => void setWake((e.target as HTMLInputElement).checked));
$("btn-clear-log").addEventListener("click", () => {
  logLines.length = 0;
  $("log").textContent = "";
});
$("btn-copy-log").addEventListener("click", async () => {
  const text = [`UA: ${navigator.userAgent}`, ...logLines].join("\n");
  try {
    await navigator.clipboard.writeText(text);
    log("log copied");
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    log("log copied (fallback)");
  }
});

const m = /^#room=([a-z2-7]+)$/.exec(location.hash);
if (m) $<HTMLInputElement>("join-code").value = m[1];
setDiag("d-vis", document.visibilityState);
log(`ready. secureContext=${window.isSecureContext} UA=${navigator.userAgent}`);
void verified; // reserved for gating features in later phases
screen("setup");
