"""Protocol-level tests for Hub: fake sockets + fake clock => deterministic, no network, no sleeps."""
import asyncio
import json
import random

from identity_store import SqliteIdentityStore
from main import CLOSE_RATE, CLOSE_REPLACED, Conn, Hub, Settings


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeWS:
    def __init__(self):
        self.raw: list[str] = []
        self.msgs: list[dict] = []
        self.closed: int | None = None

    async def send_text(self, text: str):
        if self.closed is not None:
            raise RuntimeError("closed")
        self.raw.append(text)
        try:
            self.msgs.append(json.loads(text))
        except json.JSONDecodeError:
            pass

    async def close(self, code: int = 1000):
        self.closed = code


def run(coro):
    return asyncio.run(coro)


def make_hub(**over):
    clk = Clock()
    s = Settings(db_path=":memory:", unavailable_delay=(0.5, 0.5), **over)
    hub = Hub(s, SqliteIdentityStore(":memory:"), clock=clk, rng=random.Random(7))
    return hub, clk


async def user(hub: Hub, pin: str) -> Conn:
    c = Conn(FakeWS(), pin, hub)
    await hub.attach(c)
    return c


async def send(hub: Hub, c: Conn, **msg):
    await hub.handle(c, json.dumps(msg))


def of(c: Conn, type_: str) -> list[dict]:
    return [m for m in c.ws.msgs if m["type"] == type_]


async def paired(hub: Hub, pa="1111", pb="2222"):
    a, b = await user(hub, pa), await user(hub, pb)
    await send(hub, a, type="connect", to=pb)
    rid = of(b, "incoming")[-1]["id"]
    await send(hub, b, type="accept", id=rid)
    return a, b, of(a, "session")[-1]["sid"]


# ---------------- requests ----------------


def test_valid_request_reaches_recipient_with_sender_pin():
    async def go():
        hub, _ = make_hub()
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        assert of(a, "request_update")[-1]["state"] == "sent"
        inc = of(b, "incoming")
        assert len(inc) == 1 and inc[0]["from"] == "1111"
        assert not hub.sessions  # no session until accepted

    run(go())


def test_invalid_pins_are_rejected_and_create_nothing():
    async def go():
        hub, _ = make_hub()
        a = await user(hub, "1111")
        for bad in ["12", "abcd", "12345", "", None, 1234, "١٢٣٤", "12 3", "+123", "0x12"]:
            await send(hub, a, type="connect", to=bad)
        assert [m["code"] for m in of(a, "error")] == ["bad_pin"] * 10
        assert not hub.requests and not hub.out_by_sender

    run(go())


def test_leading_zero_pins_route_correctly():
    async def go():
        hub, _ = make_hub()
        a, b = await user(hub, "0042"), await user(hub, "0007")
        await send(hub, a, type="connect", to="0007")
        assert of(b, "incoming")[0]["from"] == "0042"

    run(go())


def test_self_connection_is_refused():
    async def go():
        hub, _ = make_hub()
        a = await user(hub, "1111")
        await send(hub, a, type="connect", to="1111")
        assert of(a, "error")[-1]["code"] == "self"
        assert not hub.requests

    run(go())


def test_offline_recipient_gets_unavailable_after_a_delay_and_looks_like_a_normal_send():
    async def go():
        hub, clk = make_hub()
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="9999")  # nobody home
        await send(hub, b, type="connect", to="3333")  # also nobody home
        sent = of(a, "request_update")
        assert sent[0]["state"] == "sent"
        assert set(sent[0]) == set(of(b, "request_update")[0])  # same shape as any other ack
        await hub.sweep()
        assert len(of(a, "request_update")) == 1  # not yet: delivery is delayed
        clk.t += 0.6
        await hub.sweep()
        assert of(a, "request_update")[-1]["state"] == "unavailable"
        assert "9999" not in a.ws.raw[-1]  # response does not echo anything probe-able

    run(go())


def test_busy_recipient_is_indistinguishable_from_offline():
    async def go():
        hub, clk = make_hub()
        a, b, _ = await paired(hub)
        c = await user(hub, "3333")
        await send(hub, c, type="connect", to="1111")  # 1111 is in a session
        assert not of(a, "incoming")
        clk.t += 1
        await hub.sweep()
        assert of(c, "request_update")[-1]["state"] == "unavailable"

    run(go())


def test_duplicate_request_prevented():
    async def go():
        hub, _ = make_hub()
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        await send(hub, a, type="connect", to="2222")
        await send(hub, a, type="connect", to="4444")  # also not allowed: one outstanding request per sender
        assert [m["code"] for m in of(a, "error")] == ["pending_exists", "pending_exists"]
        assert len(of(b, "incoming")) == 1

    run(go())


def test_inbound_queue_is_capped_so_a_recipient_cannot_be_flooded():
    async def go():
        hub, clk = make_hub(max_inbound=3)
        b = await user(hub, "2222")
        senders = [await user(hub, f"10{i:02d}") for i in range(5)]
        for s_ in senders:
            await send(hub, s_, type="connect", to="2222")
        assert len(of(b, "incoming")) == 3
        clk.t += 1
        await hub.sweep()
        late = [of(s_, "request_update")[-1]["state"] for s_ in senders[3:]]
        assert late == ["unavailable", "unavailable"]

    run(go())


def test_connect_rate_limit():
    async def go():
        hub, _ = make_hub()
        a = await user(hub, "1111")
        for i in range(8):
            await send(hub, a, type="connect", to=f"90{i:02d}")
            await send(hub, a, type="cancel")
        codes = [m["code"] for m in of(a, "error")]
        assert codes.count("rate_limited") == 3  # burst of 5 allowed, the rest refused

    run(go())


# ---------------- accept / reject / expire ----------------


def test_accept_gives_both_sides_the_same_session():
    async def go():
        hub, _ = make_hub()
        a, b, sid = await paired(hub)
        sa, sb = of(a, "session")[0], of(b, "session")[0]
        assert sa["sid"] == sb["sid"] == sid and len(sid) >= 20
        assert (sa["role"], sb["role"]) == ("a", "b")  # requester = a (sends the handshake commit)
        assert (sa["peer"], sb["peer"]) == ("2222", "1111")
        assert of(a, "request_update")[-1]["state"] == "accepted"
        assert not hub.requests

    run(go())


def test_reject_notifies_sender_and_creates_no_session():
    async def go():
        hub, _ = make_hub()
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        await send(hub, b, type="reject", id=of(b, "incoming")[0]["id"])
        assert of(a, "request_update")[-1]["state"] == "rejected"
        assert not hub.sessions and not hub.requests
        assert not of(a, "session") and not of(b, "session")

    run(go())


def test_reject_cooldown_blocks_immediate_retry_silently_then_expires():
    async def go():
        hub, clk = make_hub(reject_cooldown_s=60)
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        await send(hub, b, type="reject", id=of(b, "incoming")[0]["id"])
        await send(hub, a, type="connect", to="2222")  # retry right away
        assert len(of(b, "incoming")) == 1  # B is not pestered again
        clk.t += 1
        await hub.sweep()
        assert of(a, "request_update")[-1]["state"] == "unavailable"  # and A cannot tell why
        clk.t += 61
        await hub.sweep()
        await send(hub, a, type="connect", to="2222")
        assert len(of(b, "incoming")) == 2

    run(go())


def test_requests_expire_and_cannot_be_accepted_afterwards():
    async def go():
        hub, clk = make_hub(request_ttl_s=60)
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        rid = of(b, "incoming")[0]["id"]
        clk.t += 59
        await hub.sweep()
        assert not of(a, "request_update")[1:]
        clk.t += 2
        await hub.sweep()
        assert of(a, "request_update")[-1]["state"] == "expired"
        assert of(b, "incoming_closed")[-1]["reason"] == "expired"
        await send(hub, b, type="accept", id=rid)
        assert of(b, "error")[-1]["code"] == "unknown_request"
        assert not hub.sessions

    run(go())


def test_expiry_is_enforced_even_if_the_sweeper_has_not_run_yet():
    async def go():
        hub, clk = make_hub(request_ttl_s=60)
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        rid = of(b, "incoming")[0]["id"]
        clk.t += 61  # no sweep
        await send(hub, b, type="accept", id=rid)
        assert not hub.sessions and of(b, "error")[-1]["code"] == "unknown_request"

    run(go())


def test_cancel_withdraws_request():
    async def go():
        hub, _ = make_hub()
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        rid = of(b, "incoming")[0]["id"]
        await send(hub, a, type="cancel")
        assert of(b, "incoming_closed")[-1]["reason"] == "cancelled"
        assert of(a, "request_update")[-1]["state"] == "cancelled"
        await send(hub, b, type="accept", id=rid)
        assert not hub.sessions

    run(go())


# ---------------- unauthorized manipulation ----------------


def test_only_the_addressed_identity_can_accept_or_reject():
    async def go():
        hub, _ = make_hub()
        a, b, c = await user(hub, "1111"), await user(hub, "2222"), await user(hub, "3333")
        await send(hub, a, type="connect", to="2222")
        rid = of(b, "incoming")[0]["id"]
        await send(hub, c, type="accept", id=rid)  # bystander
        await send(hub, c, type="reject", id=rid)
        await send(hub, a, type="accept", id=rid)  # the sender cannot accept their own request either
        assert [m["code"] for m in of(c, "error")] == ["unknown_request"] * 2
        assert of(a, "error")[-1]["code"] == "unknown_request"
        assert not hub.sessions and rid in hub.requests  # still pending, untouched
        assert not of(a, "request_update")[1:]  # sender was not told "rejected" by the bystander
        await send(hub, b, type="accept", id=rid)  # the real recipient still can
        assert len(hub.sessions) == 1

    run(go())


def test_malformed_ids_are_handled():
    async def go():
        hub, _ = make_hub()
        b = await user(hub, "2222")
        for bad in [None, 5, [], {}, "nope", ""]:
            await send(hub, b, type="accept", id=bad)
            await send(hub, b, type="reject", id=bad)
        assert all(m["code"] == "unknown_request" for m in of(b, "error")) and len(of(b, "error")) == 12

    run(go())


def test_concurrent_double_accept_creates_exactly_one_session():
    async def go():
        hub, _ = make_hub()
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await send(hub, a, type="connect", to="2222")
        rid = of(b, "incoming")[0]["id"]
        frame = json.dumps({"type": "accept", "id": rid})
        await asyncio.gather(hub.handle(b, frame), hub.handle(b, frame), hub.handle(b, frame))
        assert len(hub.sessions) == 1
        assert len(of(a, "session")) == 1 and len(of(b, "session")) == 1

    run(go())


def test_accepting_a_request_cancels_the_acceptors_own_pending_request():
    async def go():
        hub, _ = make_hub()
        a, b, c = await user(hub, "1111"), await user(hub, "2222"), await user(hub, "3333")
        await send(hub, a, type="connect", to="2222")  # A -> B pending
        rid_ab = of(b, "incoming")[0]["id"]
        await send(hub, c, type="connect", to="1111")  # C -> A pending
        await send(hub, a, type="accept", id=of(a, "incoming")[0]["id"])  # A accepts C
        assert of(b, "incoming_closed")[-1]["reason"] == "cancelled"  # A's own request to B was withdrawn
        await send(hub, b, type="accept", id=rid_ab)  # B can no longer accept it
        assert of(b, "error")[-1]["code"] == "unknown_request"
        assert len(hub.sessions) == 1 and not hub.requests

    run(go())


def test_entering_a_session_declines_other_pending_inbound_requests():
    async def go():
        hub, clk = make_hub()
        b = await user(hub, "2222")
        a, c = await user(hub, "1111"), await user(hub, "3333")
        await send(hub, a, type="connect", to="2222")
        await send(hub, c, type="connect", to="2222")
        await send(hub, b, type="accept", id=of(b, "incoming")[0]["id"])
        assert of(c, "request_update")[-1]["state"] == "unavailable"
        assert len(hub.sessions) == 1

    run(go())


# ---------------- relay / forged messages ----------------


def test_relay_goes_only_to_the_session_peer_and_ignores_forged_routing_fields():
    async def go():
        hub, _ = make_hub()
        a, b, sid = await paired(hub)
        c = await user(hub, "3333")  # outsider, authenticated but not in the session
        frame = json.dumps({"type": "msg", "seq": 0, "ct": "AAAA-opaque"})
        await hub.handle(a, frame)
        assert b.ws.raw[-1] == frame  # byte-for-byte
        # Outsider forges every routing field they can think of:
        for forged in (
            {"type": "msg", "sid": sid, "to": "1111", "ct": "evil"},
            {"type": "sig", "session": sid, "peer": "2222", "from": "1111", "ct": "evil"},
            {"type": "hs", "sid": sid, "ct": "evil"},
        ):
            await hub.handle(c, json.dumps(forged))
        assert all("evil" not in r for r in a.ws.raw + b.ws.raw)
        # A member forging someone else's sid still only reaches their real peer:
        forged = json.dumps({"type": "msg", "sid": "other", "to": "3333", "ct": "x"})
        await hub.handle(a, forged)
        assert b.ws.raw[-1] == forged  # routing ignored the forged "to" and still reached the real peer
        assert not any('"ct":"x"' in r.replace(" ", "") for r in c.ws.raw)
        # ...and a forged "to" pointing at yourself does not loop the frame back to you.
        n = len(a.ws.raw)
        await hub.handle(a, json.dumps({"type": "msg", "to": "1111", "ct": "y"}))
        assert len(a.ws.raw) == n

    run(go())


def test_no_relay_without_a_session():
    async def go():
        hub, _ = make_hub()
        a, b = await user(hub, "1111"), await user(hub, "2222")
        await hub.handle(a, json.dumps({"type": "msg", "ct": "x"}))
        assert not [m for m in b.ws.msgs if m["type"] == "msg"]

    run(go())


# ---------------- teardown ----------------


def test_leave_ends_session_for_both_and_stops_relay():
    async def go():
        hub, _ = make_hub()
        a, b, sid = await paired(hub)
        await send(hub, a, type="leave")
        assert of(a, "ended")[-1] == {"type": "ended", "sid": sid, "reason": "left"}
        assert of(b, "ended")[-1]["reason"] == "left"
        assert not hub.sessions and a.session_id is None and b.session_id is None
        before = len(b.ws.raw)
        await hub.handle(a, json.dumps({"type": "msg", "ct": "late"}))
        assert len(b.ws.raw) == before
        await send(hub, b, type="leave")  # duplicate LEAVE is a harmless no-op
        assert len(of(a, "ended")) == 1

    run(go())


def test_after_leave_both_stay_online_and_can_start_a_new_session():
    async def go():
        hub, _ = make_hub()
        a, b, sid = await paired(hub)
        await send(hub, a, type="leave")
        await send(hub, b, type="connect", to="1111")
        await send(hub, a, type="accept", id=of(a, "incoming")[-1]["id"])
        new = of(a, "session")[-1]["sid"]
        assert new != sid and new in hub.sessions and sid not in hub.sessions

    run(go())


def test_disconnect_ends_session_and_peer_is_told():
    async def go():
        hub, _ = make_hub()
        a, b, sid = await paired(hub)
        await hub.detach(b, "disconnect")
        assert of(a, "ended")[-1]["reason"] == "peer_disconnected"
        assert not hub.sessions and "2222" not in hub.registry
        await hub.detach(b, "disconnect")  # idempotent

    run(go())


def test_disconnect_cleans_pending_requests_both_ways():
    async def go():
        hub, _ = make_hub()
        a, b, c = await user(hub, "1111"), await user(hub, "2222"), await user(hub, "3333")
        await send(hub, a, type="connect", to="2222")
        await send(hub, c, type="connect", to="1111")
        await hub.detach(a, "disconnect")
        assert of(b, "incoming_closed")[-1]["reason"] == "cancelled"  # A's outgoing withdrawn
        assert of(c, "request_update")[-1]["state"] == "unavailable"  # request to A dies with A
        assert not hub.requests and not hub.out_by_sender and not hub.in_by_target

    run(go())


def test_second_connection_for_an_identity_replaces_the_first_visibly():
    async def go():
        hub, _ = make_hub()
        a1, b, sid = await paired(hub)
        a2 = Conn(FakeWS(), "1111", hub)
        await hub.attach(a2)
        assert of(a1, "replaced") and a1.ws.closed == CLOSE_REPLACED  # old one is told, not silently dropped
        assert of(b, "ended")[-1]["reason"] == "peer_disconnected"  # its keys lived in the old tab
        assert hub.registry["1111"] is a2 and a2.session_id is None
        await hub.detach(a1, "disconnect")  # the old socket's read loop finishing must not disturb the new one
        assert hub.registry["1111"] is a2 and not a2.closed

    run(go())


def test_session_hard_expiry():
    async def go():
        hub, clk = make_hub(session_max_s=100)
        a, b, sid = await paired(hub)
        clk.t += 99
        await hub.sweep()
        assert sid in hub.sessions
        clk.t += 2
        await hub.sweep()
        assert of(a, "ended")[-1]["reason"] == "expired" and of(b, "ended")[-1]["reason"] == "expired"
        assert not hub.sessions

    run(go())


# ---------------- misc ----------------


def test_frame_flood_closes_the_connection():
    async def go():
        hub, _ = make_hub()
        a = await user(hub, "1111")
        for _ in range(100):
            await hub.handle(a, json.dumps({"type": "ping", "t": 1}))
        assert a.closed and a.ws.closed == CLOSE_RATE
        assert "1111" not in hub.registry

    run(go())


def test_ping_pong_and_garbage_frames():
    async def go():
        hub, _ = make_hub()
        a = await user(hub, "1111")
        await hub.handle(a, json.dumps({"type": "ping", "t": 12345}))
        await hub.handle(a, "not json")
        await hub.handle(a, json.dumps([1, 2, 3]))
        await hub.handle(a, json.dumps({"type": "nonsense"}))
        await hub.handle(a, json.dumps({"type": "ping", "t": True}))
        assert of(a, "pong")[0]["t"] == 12345 and of(a, "pong")[1]["t"] is None
        assert not a.closed

    run(go())
