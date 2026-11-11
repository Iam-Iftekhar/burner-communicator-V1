import base64
import hashlib
import hmac
import json
import re
import time

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import main
from identity_store import SqliteIdentityStore, hash_token

COOKIE = "eph_id"


def build(monkeypatch, **over):
    for k in ("STUN_URLS", "TURN_URLS", "TURN_SECRET"):
        monkeypatch.delenv(k, raising=False)
    kw = dict(db_path=":memory:", unavailable_delay=(0.0, 0.0), sweep_interval_s=0.05)
    kw.update(over)
    s = main.Settings(**kw)
    store = SqliteIdentityStore(":memory:")
    return main.make_app(s, store), store


@pytest.fixture()
def client(monkeypatch):
    app, store = build(monkeypatch)
    with TestClient(app) as c:
        c.store = store
        yield c


def new_identity(c):
    c.cookies.clear()
    r = c.post("/identity")
    assert r.status_code == 200, r.text
    return r.json()["pin"], r.cookies[COOKIE]


def ws_for(c, token, **headers):
    return c.websocket_connect("/ws", headers={"cookie": f"{COOKIE}={token}", **headers})


# ---------------- identity endpoint ----------------


def test_new_user_gets_pin_and_a_locked_down_cookie(client):
    client.cookies.clear()
    r = client.post("/identity")
    assert r.status_code == 200
    body = r.json()
    assert re.fullmatch(r"[0-9]{4}", body["pin"]) and body["created"] is True
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc and "path=/" in sc and "max-age=" in sc
    token = r.cookies[COOKIE]
    assert len(token) >= 40  # 256 bits, url-safe base64
    assert token not in r.text  # the credential is never in the response body
    assert client.store.lookup(hash_token(token)) == body["pin"]


def test_cookie_is_secure_over_https_or_trusted_proxy(monkeypatch):
    app, _ = build(monkeypatch, trust_proxy=True)
    with TestClient(app) as c:
        r = c.post("/identity", headers={"x-forwarded-proto": "https"})
        assert "secure" in r.headers["set-cookie"].lower()
    app, _ = build(monkeypatch)  # proxy headers NOT trusted by default
    with TestClient(app) as c:
        r = c.post("/identity", headers={"x-forwarded-proto": "https"})
        assert "secure" not in r.headers["set-cookie"].lower()


def test_same_cookie_returns_same_pin_and_does_not_allocate_another(client):
    pin, tok = new_identity(client)
    for _ in range(3):
        r = client.post("/identity", cookies={COOKIE: tok})
        assert r.json() == {"pin": pin, "created": False}
    assert client.store.count() == 1


def test_different_users_get_different_pins(client):
    pins = {new_identity(client)[0] for _ in range(15)}
    assert len(pins) == 15


def test_pin_alone_is_not_a_credential(client):
    pin, _ = new_identity(client)
    for cookies in ({COOKIE: pin}, {COOKIE: "x" * 43}, {}):
        client.cookies.clear()
        r = client.post("/identity", cookies=cookies)
        # Presenting the PIN (or garbage) as a credential does not recover that identity;
        # the caller is simply treated as a brand-new user with a different PIN.
        assert r.json()["created"] is True and r.json()["pin"] != pin
    # and the PIN cannot open a websocket as that identity
    with ws_for(client, pin) as ws:
        assert ws.receive_json() == {"type": "auth_failed"}
        with pytest.raises(WebSocketDisconnect) as ei:
            ws.receive_text()
        assert ei.value.code == main.CLOSE_UNAUTH


def test_stale_cookie_after_server_forgets_you_gets_a_new_identity(client):
    pin, tok = new_identity(client)
    client.store.release(hash_token(tok))
    r = client.post("/identity", cookies={COOKIE: tok})
    assert r.json()["created"] is True and r.json()["pin"] != pin
    assert r.cookies[COOKIE] != tok


def test_identity_creation_is_rate_limited_per_ip_but_recovery_is_not(monkeypatch):
    app, _ = build(monkeypatch, register_per_ip=3)
    with TestClient(app) as c:
        toks = [new_identity(c)[1] for _ in range(3)]
        c.cookies.clear()
        r = c.post("/identity")
        assert r.status_code == 429 and "retry-after" in r.headers
        assert c.post("/identity", cookies={COOKIE: toks[0]}).status_code == 200  # returning users unaffected


def test_pin_exhaustion_is_a_controlled_503(monkeypatch):
    app, _ = build(monkeypatch)
    store = SqliteIdentityStore(":memory:", namespace=3)
    app = main.make_app(main.Settings(db_path=":memory:", unavailable_delay=(0, 0)), store)
    with TestClient(app) as c:
        got = [new_identity(c)[0] for _ in range(3)]
        assert sorted(got) == ["0000", "0001", "0002"]  # leading zeros preserved end to end
        c.cookies.clear()
        r = c.post("/identity")
        assert r.status_code == 503 and r.json() == {"error": "pins_exhausted"} and r.headers["retry-after"] == "60"


def test_release_frees_pin_kills_credential_and_disconnects(client):
    pin, tok = new_identity(client)
    with ws_for(client, tok) as ws:
        assert ws.receive_json() == {"type": "authed", "pin": pin}
        r = client.post("/identity/release", cookies={COOKIE: tok})
        assert r.status_code == 204
        with pytest.raises(WebSocketDisconnect) as ei:
            ws.receive_text()
        assert ei.value.code == main.CLOSE_RELEASED
    assert client.store.lookup(hash_token(tok)) is None
    with ws_for(client, tok) as ws2:
        assert ws2.receive_json() == {"type": "auth_failed"}


def test_cross_site_requests_are_refused(client):
    pin, tok = new_identity(client)
    evil = {"origin": "https://evil.example"}
    assert client.post("/identity", headers=evil, cookies={COOKIE: tok}).status_code == 403
    assert client.post("/identity/release", headers=evil, cookies={COOKIE: tok}).status_code == 403
    assert client.store.lookup(hash_token(tok)) == pin  # evil release did nothing
    same = {"origin": "http://testserver"}
    assert client.post("/identity", headers=same, cookies={COOKIE: tok}).status_code == 200


def test_cross_site_websocket_hijack_is_refused(client):
    _, tok = new_identity(client)
    with pytest.raises(WebSocketDisconnect):
        with ws_for(client, tok, origin="https://evil.example") as ws:
            ws.receive_text()
    with pytest.raises(WebSocketDisconnect):
        with ws_for(client, tok, origin="null") as ws:
            ws.receive_text()
    with ws_for(client, tok, origin="http://testserver") as ws:  # own origin is fine
        assert ws.receive_json()["type"] == "authed"


def test_proxy_forwarded_host_and_explicit_allowlist(monkeypatch):
    app, _ = build(monkeypatch, trust_proxy=True, allowed_origins=("https://extra.example",))
    with TestClient(app) as c:
        _, tok = new_identity(c)
        with ws_for(c, tok, origin="https://abc.trycloudflare.com", **{"x-forwarded-host": "abc.trycloudflare.com"}) as ws:
            assert ws.receive_json()["type"] == "authed"
    with TestClient(app) as c:
        _, tok = new_identity(c)
        with ws_for(c, tok, origin="https://extra.example") as ws:
            assert ws.receive_json()["type"] == "authed"
    app, _ = build(monkeypatch)  # trust_proxy off: X-Forwarded-Host must be ignored
    with TestClient(app) as c:
        _, tok = new_identity(c)
        with pytest.raises(WebSocketDisconnect):
            with ws_for(c, tok, origin="https://abc.trycloudflare.com", **{"x-forwarded-host": "abc.trycloudflare.com"}) as ws:
                ws.receive_text()


# ---------------- websocket flow through the real app ----------------


def test_full_request_accept_relay_leave_over_real_sockets(client):
    pa, ta = new_identity(client)
    pb, tb = new_identity(client)
    with ws_for(client, ta) as a, ws_for(client, tb) as b:
        assert a.receive_json() == {"type": "authed", "pin": pa}
        assert b.receive_json() == {"type": "authed", "pin": pb}

        a.send_json({"type": "connect", "to": pb})
        assert a.receive_json()["state"] == "sent"
        inc = b.receive_json()
        assert inc["type"] == "incoming" and inc["from"] == pa
        b.send_json({"type": "accept", "id": inc["id"]})

        assert a.receive_json()["state"] == "accepted"
        sa, sb = a.receive_json(), b.receive_json()
        assert sa["sid"] == sb["sid"] and (sa["role"], sb["role"]) == ("a", "b")

        frame = json.dumps({"type": "hs", "k": "commit", "c": "opaque"})
        a.send_text(frame)
        assert b.receive_text() == frame
        frame2 = json.dumps({"type": "msg", "seq": 0, "ct": "zzz"})
        b.send_text(frame2)
        assert a.receive_text() == frame2

        a.send_json({"type": "leave"})
        assert a.receive_json()["type"] == "ended" and b.receive_json()["reason"] == "left"
        # both still connected and usable afterwards
        b.send_json({"type": "ping", "t": 5})
        assert b.receive_json() == {"type": "pong", "t": 5}


def test_unknown_recipient_over_real_socket_gets_unavailable(client):
    _, ta = new_identity(client)
    with ws_for(client, ta) as a:
        a.receive_json()
        a.send_json({"type": "connect", "to": "0000"})
        assert a.receive_json()["state"] == "sent"
        assert a.receive_json()["state"] == "unavailable"  # delivered by the background sweeper


def test_expired_request_notifies_over_real_sockets(monkeypatch):
    app, _ = build(monkeypatch, request_ttl_s=0.2)
    with TestClient(app) as c:
        pa, ta = new_identity(c)
        pb, tb = new_identity(c)
        with ws_for(c, ta) as a, ws_for(c, tb) as b:
            a.receive_json(), b.receive_json()  # authed
            a.send_json({"type": "connect", "to": pb})
            assert a.receive_json()["state"] == "sent"
            rid = b.receive_json()["id"]
            assert a.receive_json() == {"type": "request_update", "id": rid, "state": "expired"}
            assert b.receive_json() == {"type": "incoming_closed", "id": rid, "reason": "expired"}


def test_websocket_without_cookie_is_refused_after_a_clear_message(client):
    client.cookies.clear()
    with client.websocket_connect("/ws") as ws:
        assert ws.receive_json() == {"type": "auth_failed"}
        with pytest.raises(WebSocketDisconnect) as ei:
            ws.receive_text()
        assert ei.value.code == main.CLOSE_UNAUTH


def test_second_tab_replaces_first_visibly_over_real_sockets(client):
    pa, ta = new_identity(client)
    with ws_for(client, ta) as first:
        assert first.receive_json()["type"] == "authed"
        with ws_for(client, ta) as second:
            assert second.receive_json() == {"type": "authed", "pin": pa}
            assert first.receive_json() == {"type": "replaced"}
            with pytest.raises(WebSocketDisconnect) as ei:
                first.receive_text()
            assert ei.value.code == main.CLOSE_REPLACED
            second.send_json({"type": "ping", "t": 1})
            assert second.receive_json()["type"] == "pong"


def test_oversized_frame_closes_socket(client):
    _, ta = new_identity(client)
    with ws_for(client, ta) as a:
        a.receive_json()
        a.send_text("x" * (64 * 1024 + 1))
        with pytest.raises(WebSocketDisconnect) as ei:
            a.receive_text()
        assert ei.value.code == main.CLOSE_TOO_BIG


def test_frame_flood_is_rate_limited(client):
    _, ta = new_identity(client)
    with ws_for(client, ta) as a:
        a.receive_json()
        with pytest.raises(WebSocketDisconnect) as ei:
            for _ in range(500):
                a.send_json({"type": "ping", "t": 1})
            while True:
                a.receive_text()
        assert ei.value.code == main.CLOSE_RATE


# ---------------- unchanged infrastructure ----------------


def test_ice_defaults_without_turn(client):
    body = client.get("/ice").json()
    assert body["iceServers"] == [] and body["iceTransportPolicy"] == "all" and body["turnConfigured"] is False


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
    assert client.get("/ice").json()["iceServers"][-1]["username"] != turn["username"]
    assert client.get("/ice?policy=all").json()["iceTransportPolicy"] == "all"


def test_security_headers_present(client):
    r = client.get("/healthz")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_importing_main_has_no_side_effects_but_app_attribute_works(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EPHEMERAL_DB", str(tmp_path / "x.db"))
    monkeypatch.setattr(main, "_app", None)
    assert not (tmp_path / "x.db").exists()
    assert main.app is not None  # what `uvicorn main:app` resolves
    assert (tmp_path / "x.db").exists()
