import "./style.css";
import { E2EESession, type HsMsg, type Role } from "./crypto";

// ---------- tiny DOM helpers ----------
const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
};
const show = (el: HTMLElement, on: boolean) => el.classList.toggle("hidden", !on);

// ---------- diagnostics log (never logs keys, SDP, ciphertext, message bodies or PINs) ----------
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

// ---------- state ----------
// Nothing here is written to any browser storage. The only persistent credential is the server-set
// HttpOnly cookie, which page JavaScript cannot read.
type Phase = "connecting" | "online" | "requesting" | "accepted" | "securing" | "sas" | "secure" | "disconnected";
type CallState = "idle" | "inviting" | "ringing" | "connecting" | "active";

const PHASE_TEXT: Record<Phase, string> = {
  connecting: "Connecting…",
  online: "Online",
  requesting: "Waiting for acceptance…",
  accepted: "Request accepted",
  securing: "Establishing secure connection…",
  sas: "Comparing SAS…",
  secure: "Secure session established",
  disconnected: "Disconnected",
};
let phase: Phase = "connecting";

let ws: WebSocket | null = null;
let myPin: string | null = null;
let frameQueue: Promise<void> = Promise.resolve();
let reconnectTimer: number | undefined;
let reconnectDelay = 1000;

let sess: E2EESession | null = null;
let role: Role | null = null;
let sid: string | null = null;
let peerPin: string | null = null;
let sessionOpen = false;
let localVerified = false;
let peerVerified = false;

let outgoing: { id: string | null; to: string } | null = null;
const incoming = new Map<string, { from: string; expiresAt: number }>();

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

const ready = () => sessionOpen && !!sess?.established && localVerified && peerVerified;

// ---------- screens / status ----------
function screen(name: "home" | "session" | "ended") {
  show($("screen-home"), name === "home");
  show($("screen-session"), name === "session");
  show($("screen-ended"), name === "ended");
}

function setPhase(p: Phase) {
  phase = p;
  $("conn-state").textContent = PHASE_TEXT[p];
  $("status").textContent = PHASE_TEXT[p];
  refreshConnectEnabled();
}

function setPeerMsg(text: string, isError = false) {
  const el = $("peer-pin-msg");
  el.textContent = text;
  el.classList.toggle("err", isError);
}

function identityNote(text: string | null) {
  const el = $("identity-note");
  el.textContent = text ?? "";
  show(el, !!text);
}

function refreshConnectEnabled() {
  const v = $<HTMLInputElement>("peer-pin").value;
  $<HTMLButtonElement>("btn-connect").disabled = !(phase === "online" && !outgoing && !sessionOpen && v.length === 4);
  $<HTMLButtonElement>("btn-copy-pin").disabled = !myPin;
}

function renderOutgoing(text: string | null, cancellable = true) {
  show($("outgoing"), text !== null);
  $("outgoing-text").textContent = text ?? "";
  show($("btn-cancel-req"), cancellable);
}

function renderIncoming() {
  const list = $("incoming-list");
  list.replaceChildren();
  for (const [id, r] of incoming) {
    const li = document.createElement("li");
    const who = document.createElement("div");
    who.className = "who";
    who.textContent = r.from; // textContent only
    const note = document.createElement("div");
    note.className = "muted";
    note.textContent = "wants to connect. Accept only if you expect this person.";
    const row = document.createElement("div");
    row.className = "row";
    const ok = document.createElement("button");
    ok.className = "primary";
    ok.textContent = "Accept";
    ok.addEventListener("click", () => respond(id, true));
    const no = document.createElement("button");
    no.className = "danger";
    no.textContent = "Reject";
    no.addEventListener("click", () => respond(id, false));
    row.append(ok, no);
    li.append(who, note, row);
    list.appendChild(li);
  }
  show($("incoming-modal"), incoming.size > 0);
}

function respond(id: string, accept: boolean) {
  if (!incoming.has(id)) return;
  sendRaw({ type: accept ? "accept" : "reject", id });
  incoming.delete(id);
  renderIncoming();
}

// ---------- wire helpers ----------
function sendRaw(obj: Record<string, unknown>) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function sendSecure(type: "msg" | "sig", payload: unknown) {
  if (!sess || !sess.established) return;
  const { seq, ct } = sess.seal(payload);
  sendRaw({ type, seq, ct });
}

// ---------- identity + connection ----------
async function start() {
  clearTimeout(reconnectTimer);
  setPhase("connecting");
  setDiag("d-ws", "registering identity");
  let r: Response;
  try {
    // Idempotent: with a valid recovery cookie this returns the same identity; otherwise the server allocates one.
    r = await fetch("/identity", { method: "POST", credentials: "same-origin" });
  } catch {
    log("identity request failed (network)");
    return scheduleReconnect();
  }
  if (r.status === 429) {
    identityNote("Too many new identities were requested from this network. Retrying later.");
    return scheduleReconnect(60000);
  }
  if (r.status === 503) {
    identityNote("All PINs are currently in use. Retrying shortly.");
    return scheduleReconnect(30000);
  }
  if (!r.ok) {
    log(`identity request failed (${r.status})`);
    return scheduleReconnect();
  }
  identityNote(null);
  openSocket();
}

function scheduleReconnect(delay = reconnectDelay) {
  setPhase("disconnected");
  clearTimeout(reconnectTimer);
  reconnectTimer = window.setTimeout(() => void start(), delay);
  reconnectDelay = Math.min(Math.max(delay, reconnectDelay) * 2, 15000);
  log(`reconnecting in ${(delay / 1000).toFixed(0)}s`);
}

function openSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const sock = new WebSocket(`${proto}//${location.host}/ws`); // identity travels as the HttpOnly cookie, never in the URL
  ws = sock;
  setDiag("d-ws", "connecting");
  sock.onopen = () => {
    setDiag("d-ws", "open");
    log("socket open");
    startHeartbeat();
  };
  sock.onmessage = (ev) => {
    if (sock !== ws) return;
    frameQueue = frameQueue.then(() => onFrame(ev.data as string)).catch((e) => log(`frame error: ${(e as Error).message}`));
  };
  sock.onclose = (ev) => {
    if (sock !== ws) return;
    ws = null;
    onSocketClosed(ev.code, ev.wasClean);
  };
  sock.onerror = () => log("socket error");
}

function onSocketClosed(code: number, clean: boolean) {
  setDiag("d-ws", `closed (code ${code})`);
  log(`socket closed code=${code} clean=${clean} visibility=${document.visibilityState}`);
  clearInterval(pingTimer);
  outgoing = null;
  renderOutgoing(null);
  incoming.clear();
  renderIncoming();
  if (sessionOpen) finish("Connection lost. The session cannot be resumed.");
  if (code === 4001) {
    setPhase("disconnected");
    identityNote("This PIN is open in another tab or window, which took over. Reload this page to use it here.");
    return;
  }
  if (code === 4401 || code === 4002) {
    // Credential unknown/expired or released: start() requests a fresh identity.
    reconnectDelay = 1000;
    void start();
    return;
  }
  scheduleReconnect();
}

async function onFrame(text: string) {
  let f: { type?: string; [k: string]: unknown };
  try {
    f = JSON.parse(text);
  } catch {
    return;
  }
  switch (f.type) {
    case "authed": {
      if (typeof f.pin !== "string" || !/^\d{4}$/.test(f.pin)) return;
      myPin = f.pin; // the PIN shown is whichever identity the socket actually authenticated as
      $("my-pin").textContent = myPin;
      reconnectDelay = 1000;
      log("authenticated");
      if (!sessionOpen) setPhase("online");
      refreshConnectEnabled();
      break;
    }
    case "auth_failed":
      log("server did not recognise our identity credential");
      break;
    case "replaced":
      log("this identity connected from another tab/window");
      break;
    case "incoming": {
      if (typeof f.id !== "string" || typeof f.from !== "string" || !/^\d{4}$/.test(f.from)) return;
      const secs = typeof f.expires_in === "number" ? f.expires_in : 60;
      incoming.set(f.id, { from: f.from, expiresAt: Date.now() + secs * 1000 });
      renderIncoming();
      log("incoming connection request");
      break;
    }
    case "incoming_closed":
      if (typeof f.id === "string" && incoming.delete(f.id)) {
        renderIncoming();
        log(`incoming request closed (${String(f.reason)})`);
      }
      break;
    case "request_update":
      onRequestUpdate(f.id as string, f.state as string);
      break;
    case "session":
      await onSession(f);
      break;
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
    case "ended": {
      if (!sessionOpen || f.sid !== sid) return; // stale notice for an older session
      const why: Record<string, string> = {
        left: "The other person left.",
        peer_disconnected: "The other person disconnected.",
        expired: "The session expired.",
      };
      finish(why[String(f.reason)] ?? "The session ended.");
      break;
    }
    case "error":
      onServerError(String(f.code));
      break;
  }
}

// ---------- connection requests ----------
function onServerError(code: string) {
  log(`server error: ${code}`);
  const msg: Record<string, string> = {
    bad_pin: "That is not a valid PIN.",
    self: "That is your own PIN.",
    in_session: "You are already in a session.",
    pending_exists: "You already have a request in progress.",
    rate_limited: "Too many requests. Wait a moment and try again.",
    unknown_request: "That request is no longer available.",
  };
  if (outgoing && outgoing.id === null) {
    outgoing = null;
    renderOutgoing(null);
    setPhase("online");
  }
  setPeerMsg(msg[code] ?? "Request failed.", true);
}

function onRequestUpdate(id: string, state: string) {
  if (!outgoing) return;
  if (outgoing.id !== null && outgoing.id !== id) return;
  if (state === "sent") {
    outgoing.id = id;
    setPhase("requesting");
    renderOutgoing("Request sent. Waiting for acceptance…");
    return;
  }
  if (state === "accepted") {
    setPhase("accepted");
    renderOutgoing("Request accepted.", false);
    return; // the "session" frame follows immediately
  }
  const text: Record<string, string> = {
    rejected: "Request rejected.",
    unavailable: "Recipient unavailable.",
    expired: "Request expired.",
    cancelled: "Request cancelled.",
  };
  outgoing = null;
  renderOutgoing(null);
  setPeerMsg(text[state] ?? "Request failed.", state !== "cancelled");
  setPhase("online");
}

function requestConnect() {
  const v = $<HTMLInputElement>("peer-pin").value;
  if (!/^\d{4}$/.test(v)) return setPeerMsg("Enter exactly 4 digits.", true);
  if (v === myPin) return setPeerMsg("That is your own PIN.", true);
  if (phase !== "online" || outgoing || sessionOpen) return setPeerMsg("Not ready to send a request right now.", true);
  setPeerMsg("");
  outgoing = { id: null, to: v };
  renderOutgoing("Sending request…");
  refreshConnectEnabled();
  sendRaw({ type: "connect", to: v });
}

// ---------- session start (the server only introduces the two peers; crypto authenticates them) ----------
async function onSession(f: Record<string, unknown>) {
  if (sessionOpen) return;
  if ((f.role !== "a" && f.role !== "b") || typeof f.sid !== "string" || typeof f.peer !== "string") return;
  role = f.role;
  sid = f.sid;
  peerPin = f.peer;
  sessionOpen = true;
  localVerified = peerVerified = false;
  outgoing = null;
  renderOutgoing(null);
  incoming.clear();
  renderIncoming();
  setPeerMsg("");
  sess = await E2EESession.create(role);
  $("peer-label").textContent = `Connected to PIN ${peerPin}`;
  screen("session");
  setPhase("securing");
  log(`session started as ${role}`);
  const m = sess.start(); // role "a" returns the commit; role "b" returns null and waits
  if (m) sendRaw({ type: "hs", ...m });
}

function onEstablished() {
  if (!sess) return;
  $("sas").textContent = sess.sas;
  show($("sas-box"), true);
  show($("verify-banner"), true);
  setPhase("sas");
  updateGate();
  log("key agreement complete; sending key-confirmation");
  sendSecure("msg", { t: "hello" });
}

// Chat and calls unlock only when BOTH sides have confirmed the SAS. Each side tells the other (sealed)
// once it has confirmed, and drops application messages that arrive before its own confirmation.
function updateGate() {
  const ok = ready();
  $<HTMLInputElement>("chat-input").disabled = !ok;
  $<HTMLButtonElement>("btn-send").disabled = !ok;
  const banner = $("verify-banner");
  if (!sessionOpen || !sess?.established) return;
  if (ok) {
    banner.className = "banner ok";
    banner.textContent = "Verified: both of you confirmed the codes match.";
    setPhase("secure");
  } else if (localVerified) {
    banner.className = "banner warn";
    banner.textContent = "Waiting for the other person to confirm the code…";
    setPhase("sas");
  } else {
    banner.className = "banner warn";
    banner.textContent = "Not verified: a man-in-the-middle is possible until the codes are compared.";
  }
  setCall(callState);
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
  if (p.t === "verified") {
    peerVerified = true;
    log("peer confirmed the SAS");
    updateGate();
    return;
  }
  if (!ready()) {
    log(`dropped application message before mutual SAS verification (${String(p.t)})`);
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
  $<HTMLButtonElement>("btn-call").disabled = s !== "idle" || !ready();
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
  if (callState !== "idle" || !ready()) return;
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
  if (!ready()) {
    log("dropped call signaling before mutual SAS verification");
    return;
  }
  if (p.t === "call") {
    if (p.op === "invite" && callState === "idle") {
      setCall("ringing");
    } else if (p.op === "invite") {
      sendSecure("sig", { t: "call", op: "reject" }); // busy
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
  $<HTMLAudioElement>("remote-audio").srcObject = null;
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

// ---------- leave / destroy (the socket stays open: the identity is persistent, only the session ends) ----------
function leave(reason: string) {
  if (!sessionOpen) return;
  sendRaw({ type: "leave" });
  finish(reason);
}

function finish(reason: string) {
  if (!sessionOpen) return;
  sessionOpen = false;
  endCall(false);
  sess?.destroy(); // zeroize key material
  sess = null;
  role = sid = peerPin = null;
  localVerified = peerVerified = false;
  myMsgs.clear();
  $("messages").replaceChildren();
  $<HTMLInputElement>("chat-input").value = "";
  $("sas").textContent = "--- ---";
  $("peer-label").textContent = "";
  show($("sas-box"), false);
  show($("verify-banner"), false);
  pendingIce = [];
  void setWake(false);
  $<HTMLInputElement>("wake").checked = false;
  $("ended-reason").textContent = reason;
  screen("ended");
  setPhase(ws && ws.readyState === WebSocket.OPEN ? "online" : "disconnected");
  updateGate();
  log(`session finished: ${reason}`);
}

// ---------- wiring ----------
$("connect-form").addEventListener("submit", (e) => {
  e.preventDefault();
  requestConnect();
});
$("peer-pin").addEventListener("input", () => {
  const el = $<HTMLInputElement>("peer-pin");
  const digits = el.value.replace(/\D/g, "").slice(0, 4); // keep as a STRING: leading zeros are significant
  if (digits !== el.value) el.value = digits;
  setPeerMsg(digits.length > 0 && digits.length < 4 ? "Enter exactly 4 digits." : "", false);
  refreshConnectEnabled();
});
$("btn-cancel-req").addEventListener("click", () => sendRaw({ type: "cancel" }));
$("btn-copy-pin").addEventListener("click", async () => {
  if (!myPin) return;
  try {
    await navigator.clipboard.writeText(myPin);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = myPin;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  const b = $("btn-copy-pin");
  b.textContent = "Copied";
  setTimeout(() => (b.textContent = "Copy PIN"), 1500);
});
$("btn-new-pin").addEventListener("click", async () => {
  try {
    await fetch("/identity/release", { method: "POST", credentials: "same-origin" });
  } catch {
    log("release request failed");
  }
  myPin = null;
  $("my-pin").textContent = "----";
  if (!ws) void start(); // otherwise the server closes the socket (4002) and onSocketClosed requests a new identity
});
$("btn-leave").addEventListener("click", () => leave("You left. The session was destroyed."));
$("btn-home").addEventListener("click", () => screen("home"));
$("chat-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = $<HTMLInputElement>("chat-input");
  const body = input.value.trim();
  if (!body || !ready()) return;
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
  if (!sess?.established || localVerified) return;
  localVerified = true;
  show($("sas-box"), false);
  log("SAS confirmed by user");
  sendSecure("msg", { t: "verified" });
  updateGate();
});
$("btn-sas-bad").addEventListener("click", () => {
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

// Drop incoming requests locally once their server-side lifetime has passed (the server also tells us).
setInterval(() => {
  let changed = false;
  for (const [id, r] of incoming) {
    if (Date.now() > r.expiresAt + 2000) {
      incoming.delete(id);
      changed = true;
    }
  }
  if (changed) renderIncoming();
}, 1000);

setDiag("d-vis", document.visibilityState);
log(`ready. secureContext=${window.isSecureContext} UA=${navigator.userAgent}`);
screen("home");
setPhase("connecting");
void start();
