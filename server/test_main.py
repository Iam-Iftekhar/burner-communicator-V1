import base64
import hashlib
import hmac
import json
import time

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import main


@pytest.fixture()
def client(monkeypatch):
    for k in ("STUN_URLS", "TURN_URLS", "TURN_SECRET"):
        monkeypatch.delenv(k, raising=False)
    main.rooms.clear()
    with TestClient(main.make_app()) as c:
        c._opened = []
        yield c
        for w in reversed(c._opened):  # always release client-side sockets before the app shuts down
            try:
                w.__exit__(None, None, None)
            except Exception:
                pass


def join(c, room):
    ws = c.websocket_connect("/ws")
    sock = ws.__enter__()
    c._opened.append(ws)
    sock.send_text(json.dumps({"type": "join", "room": room}))
    return ws, sock


def test_pairs_two_and_relays_opaque_frames_verbatim(client):
    room = client.post("/room").json()["room"]
    wa, a = join(client, room)
    assert json.loads(a.receive_text()) == {"type": "joined", "role": "a"}
    wb, b = join(client, room)
    assert json.loads(b.receive_text()) == {"type": "joined", "role": "b"}
    assert json.loads(a.receive_text())["type"] == "peer_joined"
    assert json.loads(b.receive_text())["type"] == "peer_joined"

    frame = json.dumps({"type": "msg", "seq": 0, "ct": "AAAA-not-inspected_by_server"})
    a.send_text(frame)
    assert b.receive_text() == frame  # byte-for-byte
    frame2 = json.dumps({"type": "sig", "seq": 3, "ct": "zzzz"})
    b.send_text(frame2)
    assert a.receive_text() == frame2


def test_third_participant_rejected(client):
    room = client.post("/room").json()["room"]
    wa, a = join(client, room)
    wb, b = join(client, room)
    wc, c3 = join(client, room)
    with pytest.raises(WebSocketDisconnect) as ei:
        c3.receive_text()
    assert ei.value.code == main.CLOSE_ROOM_FULL
    # The legitimate pair is unaffected.
    a.receive_text(), b.receive_text()


def test_unknown_room_gets_same_close_code_as_full_room(client):
    ws, sock = join(client, "doesnotexist")
    with pytest.raises(WebSocketDisconnect) as ei:
        sock.receive_text()
    assert ei.value.code == main.CLOSE_ROOM_FULL


def test_bad_first_frame_closes(client):
    with client.websocket_connect("/ws") as sock:
        sock.send_text("not json")
        with pytest.raises(WebSocketDisconnect) as ei:
            sock.receive_text()
        assert ei.value.code == main.CLOSE_BAD_JOIN


def test_leave_destroys_room_for_both_and_cannot_be_rejoined(client):
    room = client.post("/room").json()["room"]
    wa, a = join(client, room)
    wb, b = join(client, room)
    for s in (a, b):
        s.receive_text(), s.receive_text()
    a.send_text(json.dumps({"type": "leave"}))
    assert json.loads(b.receive_text())["type"] == "ended"
    with pytest.raises(WebSocketDisconnect) as ei:
        b.receive_text()
    assert ei.value.code == main.CLOSE_PEER_LEFT
    assert room not in main.rooms
    # Reopening the destroyed room is impossible.
    wc, c3 = join(client, room)
    with pytest.raises(WebSocketDisconnect) as ei2:
        c3.receive_text()
    assert ei2.value.code == main.CLOSE_ROOM_FULL


def test_abrupt_disconnect_destroys_room(client):
    room = client.post("/room").json()["room"]
    wa, a = join(client, room)
    wb, b = join(client, room)
    for s in (a, b):
        s.receive_text(), s.receive_text()
    wa.__exit__(None, None, None)  # drop without sending leave
    client._opened.remove(wa)
    assert json.loads(b.receive_text())["type"] == "ended"
    assert room not in main.rooms


def test_oversized_frame_closes_socket(client):
    room = client.post("/room").json()["room"]
    wa, a = join(client, room)
    a.receive_text()
    a.send_text("x" * (main.MAX_FRAME_BYTES + 1))
    with pytest.raises(WebSocketDisconnect) as ei:
        a.receive_text()
    assert ei.value.code == main.CLOSE_TOO_BIG


def test_flood_is_rate_limited(client):
    room = client.post("/room").json()["room"]
    wa, a = join(client, room)
    a.receive_text()
    with pytest.raises(WebSocketDisconnect) as ei:
        for _ in range(500):
            a.send_text(json.dumps({"type": "msg", "ct": "x"}))
        a.receive_text()
    assert ei.value.code == main.CLOSE_RATE


def test_ping_pong_echoes_client_timestamp(client):
    room = client.post("/room").json()["room"]
    wa, a = join(client, room)
    a.receive_text()
    a.send_text(json.dumps({"type": "ping", "t": 12345}))
    assert json.loads(a.receive_text()) == {"type": "pong", "t": 12345}


def test_room_codes_are_unique_and_high_entropy(client):
    codes = {client.post("/room").json()["room"] for _ in range(200)}
    assert len(codes) == 200
    assert all(len(c) >= 16 for c in codes)


def test_ice_defaults_without_turn(client):
    body = client.get("/ice").json()
    assert body["iceServers"] == []
    assert body["iceTransportPolicy"] == "all"
    assert body["turnConfigured"] is False


def test_ice_turn_credentials_are_valid_hmac_and_relay_by_default(client, monkeypatch):
    monkeypatch.setenv("TURN_URLS", "turns:turn.example.com:443?transport=tcp,turn:turn.example.com:3478")
    monkeypatch.setenv("TURN_SECRET", "s3cret")
    body = client.get("/ice").json()
    assert body["iceTransportPolicy"] == "relay"
    turn = body["iceServers"][-1]
    expiry = int(turn["username"].split(":")[0])
    assert 0 < expiry - time.time() <= 601
    expect = base64.b64encode(hmac.new(b"s3cret", turn["username"].encode(), hashlib.sha1).digest()).decode()
    assert turn["credential"] == expect
    # Credentials differ per call.
    assert client.get("/ice").json()["iceServers"][-1]["username"] != turn["username"]
    # Client may opt in to direct connections, only via explicit parameter.
    assert client.get("/ice?policy=all").json()["iceTransportPolicy"] == "all"


def test_security_headers_present(client):
    r = client.get("/healthz")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in r.headers["content-security-policy"]
