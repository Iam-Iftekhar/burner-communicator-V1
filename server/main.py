"""Ephemeral spike relay: PIN identities, connection requests, sessions, opaque relay.

Responsibilities are kept separate on purpose:
  * PIN        = public routing label. Authenticates nothing.
  * Cookie     = 256-bit recovery token (HttpOnly). Proves "I am the owner of this PIN" to THIS server.
  * E2EE + SAS = proves who the peer is to the OTHER USER. The server never participates in it.
The server never reads relayed payloads; it only routes frames between the two members of a session,
and the session is always derived from server-side connection state, never from client-supplied fields.

Not production: single process, in-memory request/session state, SQLite identities.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import re
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from identity_store import IdentityStore, PinsExhausted, SqliteIdentityStore, hash_token

log = logging.getLogger("ephemeral")

PIN_RE = re.compile(r"^[0-9]{4}$")
RELAY_TYPES = frozenset({"hs", "msg", "sig"})

# WebSocket close codes (4000-4999 are application-defined)
CLOSE_ENDED = 4000
CLOSE_REPLACED = 4001  # same identity connected from elsewhere
CLOSE_RELEASED = 4002  # identity released by its owner
CLOSE_UNAUTH = 4401
CLOSE_TOO_BIG = 4413
CLOSE_RATE = 4429


def _f(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


@dataclass
class Settings:
    db_path: str = "ephemeral-identities.db"
    identity_ttl_s: float = 30 * 86400
    pin_cooldown_s: float = 600
    unclaimed_ttl_s: float = 300
    request_ttl_s: float = 60
    reject_cooldown_s: float = 60
    session_max_s: float = 7200
    max_inbound: int = 3
    connect_burst: float = 5
    connect_refill_per_s: float = 1 / 6
    frame_burst: float = 40
    frame_refill_per_s: float = 20
    register_per_ip: int = 20
    register_window_s: float = 3600
    unavailable_delay: tuple[float, float] = (0.8, 2.0)
    trust_proxy: bool = False
    allowed_origins: tuple[str, ...] = ()
    max_frame_bytes: int = 64 * 1024
    sweep_interval_s: float = 0.25
    cookie_name: str = "eph_id"

    @classmethod
    def from_env(cls) -> "Settings":
        origins = tuple(o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip())
        return cls(
            db_path=os.environ.get("EPHEMERAL_DB", cls.db_path),
            identity_ttl_s=_f("IDENTITY_TTL_DAYS", 30) * 86400,
            pin_cooldown_s=_f("PIN_COOLDOWN_S", cls.pin_cooldown_s),
            request_ttl_s=_f("REQUEST_TTL_S", cls.request_ttl_s),
            reject_cooldown_s=_f("REJECT_COOLDOWN_S", cls.reject_cooldown_s),
            session_max_s=_f("SESSION_MAX_S", cls.session_max_s),
            register_per_ip=int(_f("REGISTER_PER_IP_HOUR", cls.register_per_ip)),
            trust_proxy=os.environ.get("TRUST_PROXY", "") == "1",
            allowed_origins=origins,
        )


class Bucket:
    def __init__(self, capacity: float, refill_per_s: float, clock: Callable[[], float]) -> None:
        self.capacity, self.rate, self.clock = capacity, refill_per_s, clock
        self.tokens = capacity
        self.last = clock()

    def take(self) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class SlidingLimiter:
    def __init__(self, limit: int, window_s: float, clock: Callable[[], float]) -> None:
        self.limit, self.window, self.clock = limit, window_s, clock
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self.clock()
        q = self.hits[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


@dataclass
class Request_:
    id: str
    frm: str
    to: str
    expires: float  # for synthetic requests: when to deliver the "unavailable" answer
    synthetic: bool = False


@dataclass
class Session:
    a: str  # requester
    b: str  # acceptor
    created: float


class Conn:
    def __init__(self, ws: Any, pin: str, hub: "Hub") -> None:
        self.ws = ws
        self.pin = pin
        self.session_id: str | None = None
        self.closed = False
        self.frames = Bucket(hub.s.frame_burst, hub.s.frame_refill_per_s, hub.clock)
        self.connects = Bucket(hub.s.connect_burst, hub.s.connect_refill_per_s, hub.clock)
        self.last_touch = hub.clock()


Note = tuple["Conn | None", dict]


class Hub:
    """All connection-request and session state. Single event loop => each synchronous block below is atomic."""

    def __init__(
        self,
        settings: Settings,
        store: IdentityStore,
        clock: Callable[[], float] = time.monotonic,
        rng: random.Random | None = None,
    ) -> None:
        self.s = settings
        self.store = store
        self.clock = clock
        self.rng = rng or random.Random()
        self.registry: dict[str, Conn] = {}  # pin -> the ONE active connection for that identity
        self.requests: dict[str, Request_] = {}
        self.out_by_sender: dict[str, str] = {}
        self.in_by_target: dict[str, set[str]] = {}
        self.sessions: dict[str, Session] = {}
        self.reject_until: dict[tuple[str, str], float] = {}
        self._last_purge = clock()

    # ---------- sending ----------

    async def _send(self, conn: Conn | None, obj: dict) -> None:
        if conn is None or conn.closed:
            return
        try:
            await conn.ws.send_text(json.dumps(obj, separators=(",", ":")))
        except Exception:
            pass

    async def _flush(self, notes: list[Note]) -> None:
        for conn, obj in notes:
            await self._send(conn, obj)

    async def _error(self, conn: Conn, code: str) -> None:
        await self._send(conn, {"type": "error", "code": code})

    # ---------- connection lifecycle ----------

    async def attach(self, conn: Conn) -> None:
        """Register an authenticated socket. A second socket for the same identity REPLACES the first,
        explicitly and visibly (the old one is told), never silently coexisting."""
        old = self.registry.get(conn.pin)
        if old is not None and old is not conn:
            await self.detach(old, "replaced", close_code=CLOSE_REPLACED)
        self.registry[conn.pin] = conn
        await self._send(conn, {"type": "authed", "pin": conn.pin})

    async def detach(self, conn: Conn, reason: str, close_code: int | None = None) -> None:
        """Idempotent teardown: invalidates the transport association and everything hanging off it."""
        if conn.closed:
            return
        if reason == "replaced":
            await self._send(conn, {"type": "replaced"})
        conn.closed = True
        if self.registry.get(conn.pin) is conn:
            del self.registry[conn.pin]
        notes = self._clear_requests(conn.pin)
        sid, conn.session_id = conn.session_id, None
        await self._flush(notes)
        if sid:
            await self._end_session(sid, "peer_disconnected")
        if close_code is not None:
            try:
                await conn.ws.close(code=close_code)
            except Exception:
                pass

    # ---------- request bookkeeping ----------

    def _drop_request(self, req: Request_) -> None:
        self.requests.pop(req.id, None)
        if self.out_by_sender.get(req.frm) == req.id:
            del self.out_by_sender[req.frm]
        pending = self.in_by_target.get(req.to)
        if pending is not None:
            pending.discard(req.id)
            if not pending:
                del self.in_by_target[req.to]

    def _clear_requests(self, pin: str) -> list[Note]:
        """Drop everything pending for/from this identity (it disconnected or entered a session)."""
        notes: list[Note] = []
        rid = self.out_by_sender.get(pin)
        if rid is not None:
            req = self.requests.get(rid)
            if req is not None:
                self._drop_request(req)
                if not req.synthetic:
                    notes.append((self.registry.get(req.to), {"type": "incoming_closed", "id": req.id, "reason": "cancelled"}))
            else:
                self.out_by_sender.pop(pin, None)
        for rid in list(self.in_by_target.get(pin, ())):
            req = self.requests.get(rid)
            if req is not None:
                self._drop_request(req)
                notes.append((self.registry.get(req.frm), {"type": "request_update", "id": req.id, "state": "unavailable"}))
        return notes

    # ---------- frame handling ----------

    async def handle(self, conn: Conn, text: str) -> None:
        if conn.closed:
            return
        if not conn.frames.take():
            await self.detach(conn, "rate_limited", close_code=CLOSE_RATE)
            return
        try:
            msg = json.loads(text)
        except json.JSONDecodeError:
            return
        if not isinstance(msg, dict):
            return
        kind = msg.get("type")
        if kind in RELAY_TYPES:
            await self._relay(conn, text)
        elif kind == "connect":
            await self._connect(conn, msg.get("to"))
        elif kind == "accept":
            await self._accept(conn, msg.get("id"))
        elif kind == "reject":
            await self._reject(conn, msg.get("id"))
        elif kind == "cancel":
            await self._cancel(conn)
        elif kind == "leave":
            if conn.session_id:
                await self._end_session(conn.session_id, "left")
        elif kind == "ping":
            t = msg.get("t")
            await self._send(conn, {"type": "pong", "t": t if isinstance(t, (int, float)) and not isinstance(t, bool) else None})
            now = self.clock()
            if now - conn.last_touch > 600:  # keep a long-lived connection's identity from idling out
                conn.last_touch = now
                self.store.touch(conn.pin)

    async def _relay(self, conn: Conn, text: str) -> None:
        # The destination is derived from SERVER-SIDE state. Any sid/to/from fields in the frame are ignored.
        sid = conn.session_id
        sess = self.sessions.get(sid) if sid else None
        if sess is None:
            return
        peer = self.registry.get(sess.b if conn.pin == sess.a else sess.a)
        if peer is not None and peer.session_id == sid and not peer.closed:
            try:
                await peer.ws.send_text(text)  # verbatim, opaque
            except Exception:
                pass

    async def _connect(self, conn: Conn, to: Any) -> None:
        now = self.clock()
        if not isinstance(to, str) or not PIN_RE.fullmatch(to):
            return await self._error(conn, "bad_pin")
        if to == conn.pin:
            return await self._error(conn, "self")
        if conn.session_id:
            return await self._error(conn, "in_session")
        if conn.pin in self.out_by_sender:
            return await self._error(conn, "pending_exists")
        if not conn.connects.take():
            return await self._error(conn, "rate_limited")

        rid = secrets.token_urlsafe(16)
        target = self.registry.get(to)
        eligible = (
            target is not None
            and not target.closed
            and target.session_id is None
            and len(self.in_by_target.get(to, ())) < self.s.max_inbound
            and self.reject_until.get((conn.pin, to), 0) <= now
        )
        if eligible:
            req = Request_(rid, conn.pin, to, now + self.s.request_ttl_s)
            self.requests[rid] = req
            self.out_by_sender[conn.pin] = rid
            self.in_by_target.setdefault(to, set()).add(rid)
            await self._send(conn, {"type": "request_update", "id": rid, "state": "sent"})
            await self._send(target, {"type": "incoming", "id": rid, "from": conn.pin, "expires_in": int(self.s.request_ttl_s)})
        else:
            # Unknown, offline, busy, full inbox, or recently rejected all look identical to the sender:
            # same "sent" ack now, then "unavailable" after a jittered delay. Limits what probing reveals.
            lo, hi = self.s.unavailable_delay
            self.requests[rid] = Request_(rid, conn.pin, to, now + self.rng.uniform(lo, hi), synthetic=True)
            self.out_by_sender[conn.pin] = rid
            await self._send(conn, {"type": "request_update", "id": rid, "state": "sent"})

    def _find_request_for(self, conn: Conn, rid: Any) -> Request_ | None:
        """Only the identity the request is addressed to may act on it. Unknown / not-yours / expired /
        synthetic all return None so callers answer them identically (no oracle)."""
        if not isinstance(rid, str):
            return None
        req = self.requests.get(rid)
        if req is None or req.synthetic or req.to != conn.pin or req.expires <= self.clock():
            return None
        return req

    async def _accept(self, conn: Conn, rid: Any) -> None:
        req = self._find_request_for(conn, rid)
        if req is None:
            return await self._error(conn, "unknown_request")
        requester = self.registry.get(req.frm)
        if conn.session_id or requester is None or requester.closed or requester.session_id:
            self._drop_request(req)
            return await self._error(conn, "unknown_request")
        self._drop_request(req)  # consumed: a replayed/duplicate accept now fails
        notes = self._clear_requests(conn.pin) + self._clear_requests(req.frm)
        sid = secrets.token_urlsafe(16)
        self.sessions[sid] = Session(a=req.frm, b=conn.pin, created=self.clock())
        requester.session_id = conn.session_id = sid
        await self._flush(notes)
        await self._send(requester, {"type": "request_update", "id": req.id, "state": "accepted"})
        await self._send(requester, {"type": "session", "sid": sid, "role": "a", "peer": conn.pin})
        await self._send(conn, {"type": "session", "sid": sid, "role": "b", "peer": req.frm})

    async def _reject(self, conn: Conn, rid: Any) -> None:
        req = self._find_request_for(conn, rid)
        if req is None:
            return await self._error(conn, "unknown_request")
        self._drop_request(req)
        self.reject_until[(req.frm, req.to)] = self.clock() + self.s.reject_cooldown_s
        await self._send(self.registry.get(req.frm), {"type": "request_update", "id": req.id, "state": "rejected"})

    async def _cancel(self, conn: Conn) -> None:
        rid = self.out_by_sender.get(conn.pin)
        req = self.requests.get(rid) if rid else None
        if req is None:
            return
        self._drop_request(req)
        if not req.synthetic:
            await self._send(self.registry.get(req.to), {"type": "incoming_closed", "id": req.id, "reason": "cancelled"})
        await self._send(conn, {"type": "request_update", "id": req.id, "state": "cancelled"})

    async def _end_session(self, sid: str, reason: str) -> None:
        """Centralized and idempotent: whoever calls first wins, later callers are no-ops."""
        sess = self.sessions.pop(sid, None)
        if sess is None:
            return
        for pin in (sess.a, sess.b):
            c = self.registry.get(pin)
            if c is not None and c.session_id == sid:
                c.session_id = None
                await self._send(c, {"type": "ended", "sid": sid, "reason": reason})

    # ---------- periodic work ----------

    async def sweep(self) -> None:
        now = self.clock()
        for req in list(self.requests.values()):
            if req.synthetic:
                if now >= req.expires:
                    self._drop_request(req)
                    await self._send(self.registry.get(req.frm), {"type": "request_update", "id": req.id, "state": "unavailable"})
            elif now >= req.expires:
                self._drop_request(req)
                await self._send(self.registry.get(req.frm), {"type": "request_update", "id": req.id, "state": "expired"})
                await self._send(self.registry.get(req.to), {"type": "incoming_closed", "id": req.id, "reason": "expired"})
        for sid, sess in list(self.sessions.items()):
            if now - sess.created > self.s.session_max_s:
                await self._end_session(sid, "expired")
        for key, until in list(self.reject_until.items()):
            if until <= now:
                del self.reject_until[key]
        if now - self._last_purge > 60:
            self._last_purge = now
            self.store.purge()


# ---------- HTTP / WebSocket layer ----------


def make_app(settings: Settings | None = None, store: IdentityStore | None = None, clock: Callable[[], float] = time.monotonic) -> FastAPI:
    s = settings or Settings.from_env()
    store = store or SqliteIdentityStore(
        s.db_path, identity_ttl_s=s.identity_ttl_s, cooldown_s=s.pin_cooldown_s, unclaimed_ttl_s=s.unclaimed_ttl_s
    )
    hub = Hub(s, store, clock=clock)
    register_limit = SlidingLimiter(s.register_per_ip, s.register_window_s, clock)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async def sweeper() -> None:
            while True:
                await asyncio.sleep(s.sweep_interval_s)
                try:
                    await hub.sweep()
                except Exception as e:  # never let the sweeper die
                    log.warning("sweep failed: %s", type(e).__name__)

        task = asyncio.create_task(sweeper())
        try:
            yield
        finally:
            task.cancel()

    app = FastAPI(title="Ephemeral relay (spike)", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.hub = hub
    app.state.store = store
    app.state.settings = s

    def origin_ok(headers: Any) -> bool:
        """Blocks cross-site WebSocket hijacking and cross-site POSTs. Requests without an Origin header
        (non-browser clients) are allowed: they cannot carry a victim's cookie in the first place."""
        origin = headers.get("origin")
        if not origin:
            return True
        if origin in s.allowed_origins:
            return True
        allowed = {headers.get("host", "").lower()}
        if s.trust_proxy and headers.get("x-forwarded-host"):
            allowed.add(headers["x-forwarded-host"].split(",")[0].strip().lower())
        return urlparse(origin).netloc.lower() in allowed

    def is_https(request: Request) -> bool:
        return request.url.scheme == "https" or (s.trust_proxy and request.headers.get("x-forwarded-proto") == "https")

    def client_ip(request: Request) -> str:
        if s.trust_proxy and request.headers.get("x-forwarded-for"):
            return request.headers["x-forwarded-for"].split(",")[-1].strip()  # entry added by our one trusted proxy
        return request.client.host if request.client else "unknown"

    def set_identity_cookie(resp: Response, token: str, request: Request) -> None:
        resp.set_cookie(
            s.cookie_name, token, max_age=int(s.identity_ttl_s), httponly=True, samesite="strict",
            secure=is_https(request), path="/",
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Permissions-Policy"] = "microphone=(self)"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' ws: wss:; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; media-src 'self' blob:; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        return resp

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.post("/identity")
    async def ensure_identity(request: Request) -> Response:
        """Idempotent. With a valid recovery cookie: return the existing identity. Otherwise allocate a new one."""
        if not origin_ok(request.headers):
            return JSONResponse({"error": "bad_origin"}, status_code=403)
        token = request.cookies.get(s.cookie_name)
        if token:
            pin = store.lookup(hash_token(token))
            if pin:
                store.touch(pin)
                resp = JSONResponse({"pin": pin, "created": False})
                set_identity_cookie(resp, token, request)  # sliding lifetime
                return resp
        if not register_limit.allow(client_ip(request)):
            return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": str(int(s.register_window_s))})
        new_token = secrets.token_urlsafe(32)  # 256 bits from the OS CSPRNG
        try:
            pin = store.allocate(hash_token(new_token))
        except PinsExhausted:
            return JSONResponse({"error": "pins_exhausted"}, status_code=503, headers={"Retry-After": "60"})
        resp = JSONResponse({"pin": pin, "created": True})
        set_identity_cookie(resp, new_token, request)
        return resp

    @app.post("/identity/release")
    async def release_identity(request: Request) -> Response:
        if not origin_ok(request.headers):
            return JSONResponse({"error": "bad_origin"}, status_code=403)
        token = request.cookies.get(s.cookie_name)
        pin = store.release(hash_token(token)) if token else None
        if pin:
            conn = hub.registry.get(pin)
            if conn is not None:
                await hub.detach(conn, "released", close_code=CLOSE_RELEASED)
        resp = Response(status_code=204)
        resp.delete_cookie(s.cookie_name, path="/")
        return resp

    @app.get("/ice")
    async def ice(policy: str = "") -> JSONResponse:
        """ICE configuration. Relay-only by default when TURN is configured (hides peer IPs)."""
        servers: list[dict] = []
        stun = [u for u in os.environ.get("STUN_URLS", "").split(",") if u.strip()]
        turn = [u for u in os.environ.get("TURN_URLS", "").split(",") if u.strip()]
        secret = os.environ.get("TURN_SECRET", "")
        if stun:
            servers.append({"urls": stun})
        if turn and secret:
            ttl = int(os.environ.get("TURN_TTL_S", "600"))
            username = f"{int(time.time()) + ttl}:{secrets.token_hex(8)}"
            cred = base64.b64encode(hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()).decode()
            servers.append({"urls": turn, "username": username, "credential": cred})
        default_policy = "relay" if (turn and secret) else "all"
        chosen = policy if policy in ("relay", "all") else default_policy
        return JSONResponse({"iceServers": servers, "iceTransportPolicy": chosen, "turnConfigured": bool(turn and secret)})

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        if not origin_ok(ws.headers):
            log.warning("rejected websocket with Origin %r (set ALLOWED_ORIGINS if this is your own URL)", ws.headers.get("origin"))
            await ws.close(code=1008)  # refused before accept => HTTP 403
            return
        await ws.accept()
        token = ws.cookies.get(s.cookie_name)
        pin = store.lookup(hash_token(token)) if token else None
        if pin is None:
            await ws.send_text(json.dumps({"type": "auth_failed"}))
            await ws.close(code=CLOSE_UNAUTH)
            return
        store.touch(pin, claim=True)
        conn = Conn(ws, pin, hub)
        await hub.attach(conn)
        try:
            while not conn.closed:
                text = await ws.receive_text()
                if len(text.encode()) > s.max_frame_bytes:
                    await hub.detach(conn, "too_big", close_code=CLOSE_TOO_BIG)
                    break
                await hub.handle(conn, text)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            await hub.detach(conn, "disconnect")

    static_dir = Path(os.environ.get("STATIC_DIR", Path(__file__).resolve().parent.parent / "client" / "dist"))
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    # Lazy so `import main` in tests has no side effects (no DB file), while `uvicorn main:app` still works.
    global _app
    if name == "app":
        if _app is None:
            _app = make_app()
        return _app
    raise AttributeError(name)
