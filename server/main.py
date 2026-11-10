"""Phase 0 spike relay.

Deliberately tiny. It does only what the real server's relay path must do:
  * pair exactly two sockets in a room identified by a random code,
  * forward opaque frames between them without inspecting payloads,
  * destroy the room when either side leaves or disconnects,
  * hand out short-lived TURN credentials (TURN REST scheme).

It holds no keys and no plaintext. It is NOT the production server: no Redis, no PIN allocation,
no identity tokens, no rate limiting beyond a per-socket bucket. Those are Phase 2.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

MAX_FRAME_BYTES = 64 * 1024
JOIN_TIMEOUT_S = 5.0
ROOM_TTL_S = 15 * 60
# Per-socket token bucket: burst 40 frames, refill 20/s.
BUCKET_CAPACITY = 40.0
BUCKET_REFILL = 20.0

# Close codes (4000-4999 are application-defined).
CLOSE_BAD_JOIN = 4400
CLOSE_ROOM_FULL = 4409
CLOSE_TOO_BIG = 4413
CLOSE_RATE = 4429
CLOSE_PEER_LEFT = 4000
CLOSE_EXPIRED = 4408


class Room:
    def __init__(self, code: str) -> None:
        self.code = code
        self.created = time.monotonic()
        self.sockets: dict[str, WebSocket] = {}  # role -> socket
        self.destroyed = False


rooms: dict[str, Room] = {}
rooms_lock = asyncio.Lock()


def new_code() -> str:
    # 80 bits, base32 without padding. A spike-only stand-in for the PIN/session machinery.
    return base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=").lower()


async def destroy_room(room: Room, reason: int = CLOSE_PEER_LEFT) -> None:
    """Idempotent. Mirrors the future centralized destroy_session()."""
    async with rooms_lock:
        if room.destroyed:
            return
        room.destroyed = True
        rooms.pop(room.code, None)
        socks = list(room.sockets.values())
        room.sockets.clear()
    for ws in socks:
        try:
            await ws.send_text(json.dumps({"type": "ended"}))
            await ws.close(code=reason)
        except Exception:
            pass


class Bucket:
    def __init__(self) -> None:
        self.tokens = BUCKET_CAPACITY
        self.last = time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(BUCKET_CAPACITY, self.tokens + (now - self.last) * BUCKET_REFILL)
        self.last = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


def make_app() -> FastAPI:
    app = FastAPI(title="Ephemeral Phase 0 relay", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request, call_next):
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

    @app.post("/room")
    async def create_room() -> dict:
        async with rooms_lock:
            code = new_code()
            rooms[code] = Room(code)
        return {"room": code}

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
        return JSONResponse(
            {"iceServers": servers, "iceTransportPolicy": chosen, "turnConfigured": bool(turn and secret)}
        )

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await ws.accept()
        room: Room | None = None
        role: str | None = None
        bucket = Bucket()
        try:
            # First frame must be {"type":"join","room":"<code>"} (never in the URL).
            try:
                first = await asyncio.wait_for(ws.receive_text(), timeout=JOIN_TIMEOUT_S)
                msg = json.loads(first)
                code = msg["room"]
                if msg.get("type") != "join" or not isinstance(code, str):
                    raise ValueError
            except (asyncio.TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                await ws.close(code=CLOSE_BAD_JOIN)
                return

            async with rooms_lock:
                room = rooms.get(code)
                if room is None or room.destroyed:
                    room = None
                elif time.monotonic() - room.created > ROOM_TTL_S:
                    room = None
                elif len(room.sockets) >= 2:
                    room = None
                    full = True
                else:
                    role = "a" if "a" not in room.sockets else "b"
                    room.sockets[role] = ws
            if room is None or role is None:
                # Same response for unknown/expired/full so room codes cannot be probed for state.
                await ws.close(code=CLOSE_ROOM_FULL)
                return

            await ws.send_text(json.dumps({"type": "joined", "role": role}))
            if len(room.sockets) == 2:
                for r, sock in list(room.sockets.items()):
                    try:
                        await sock.send_text(json.dumps({"type": "peer_joined"}))
                    except Exception:
                        pass

            while True:
                text = await ws.receive_text()
                if len(text.encode()) > MAX_FRAME_BYTES:
                    await ws.close(code=CLOSE_TOO_BIG)
                    break
                if not bucket.take():
                    await ws.close(code=CLOSE_RATE)
                    break
                if time.monotonic() - room.created > ROOM_TTL_S:
                    await destroy_room(room, CLOSE_EXPIRED)
                    break
                # Only the envelope type is read for routing; payload is relayed verbatim.
                try:
                    kind = json.loads(text).get("type")
                except (json.JSONDecodeError, AttributeError):
                    continue
                if kind == "leave":
                    break
                if kind == "ping":
                    await ws.send_text(json.dumps({"type": "pong", "t": json.loads(text).get("t")}))
                    continue
                if kind not in ("hs", "msg", "sig"):
                    continue
                peer = room.sockets.get("b" if role == "a" else "a")
                if peer is not None:
                    try:
                        await peer.send_text(text)
                    except Exception:
                        pass
        except WebSocketDisconnect:
            pass
        finally:
            if room is not None:
                await destroy_room(room)

    static_dir = Path(os.environ.get("STATIC_DIR", Path(__file__).resolve().parent.parent / "client" / "dist"))
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
    return app


app = make_app()
