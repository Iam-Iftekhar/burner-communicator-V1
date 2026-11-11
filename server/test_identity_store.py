import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from identity_store import PinsExhausted, SqliteIdentityStore, hash_token


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def mem(**kw):
    clk = kw.pop("clock", None) or Clock()
    return SqliteIdentityStore(":memory:", clock=clk, **kw), clk


def test_assigns_a_four_digit_pin():
    s, _ = mem()
    pin = s.allocate(hash_token("tok"))
    assert re.fullmatch(r"[0-9]{4}", pin)
    assert s.lookup(hash_token("tok")) == pin


def test_pins_are_unique_across_users():
    s, _ = mem()
    pins = [s.allocate(hash_token(f"t{i}")) for i in range(500)]
    assert len(set(pins)) == 500


def test_unknown_token_has_no_identity():
    s, _ = mem()
    s.allocate(hash_token("real"))
    assert s.lookup(hash_token("fake")) is None


def test_concurrent_registration_never_duplicates(tmp_path):
    # File-backed on purpose: each thread gets its own SQLite connection, so this exercises
    # real cross-connection locking, not a Python lock around one shared connection.
    path = str(tmp_path / "ids.db")
    s = SqliteIdentityStore(path)
    with ThreadPoolExecutor(max_workers=32) as ex:
        pins = list(ex.map(lambda i: s.allocate(hash_token(f"tok{i}")), range(200)))
    assert len(set(pins)) == 200
    assert s.count() == 200


def test_concurrent_allocation_in_a_tiny_namespace_never_oversubscribes(tmp_path):
    s = SqliteIdentityStore(str(tmp_path / "ids.db"), namespace=10)

    def grab(i):
        try:
            return s.allocate(hash_token(f"tok{i}"))
        except PinsExhausted:
            return None

    with ThreadPoolExecutor(max_workers=16) as ex:
        out = list(ex.map(grab, range(40)))
    got = [p for p in out if p]
    assert len(got) == 10 and len(set(got)) == 10  # exactly the namespace, no duplicates
    assert out.count(None) == 30


def test_leading_zero_pins_are_allocatable_and_kept_as_strings():
    s, _ = mem(namespace=10)  # PINs 0000..0009
    pins = {s.allocate(hash_token(f"t{i}")) for i in range(10)}
    assert pins == {f"000{i}" for i in range(10)}
    assert "0000" in pins


def test_full_namespace_exhaustion_returns_controlled_error():
    s, clk = mem()
    con = s._mem
    con.executemany(
        "INSERT INTO identities(pin, token_hash, created, last_seen, claimed) VALUES (?, ?, ?, ?, 1)",
        [(f"{n:04d}", f"h{n}", clk.t, clk.t) for n in range(9_999)],
    )
    last = s.allocate(hash_token("last"))
    assert last == "9999"  # the only one left; also proves 9999 is reachable
    with pytest.raises(PinsExhausted):
        s.allocate(hash_token("one-too-many"))
    assert s.count() == 10_000


def test_identity_persists_across_store_restart(tmp_path):
    path = str(tmp_path / "ids.db")
    a = SqliteIdentityStore(path)
    pin = a.allocate(hash_token("my-token"))
    del a
    b = SqliteIdentityStore(path)  # "server restart"
    assert b.lookup(hash_token("my-token")) == pin
    assert b.allocate(hash_token("someone-else")) != pin


def test_raw_token_is_never_stored(tmp_path):
    path = str(tmp_path / "ids.db")
    s = SqliteIdentityStore(path)
    token = "super-secret-token-value-123"
    s.allocate(hash_token(token))
    con = sqlite3.connect(path)
    dump = "\n".join(con.iterdump())
    con.close()
    assert token not in dump
    assert hash_token(token) in dump


def test_release_puts_pin_in_cooldown_then_frees_it():
    s, clk = mem(namespace=1, cooldown_s=600)
    s.allocate(hash_token("a"))
    assert s.release(hash_token("a")) == "0000"
    assert s.lookup(hash_token("a")) is None  # credential is dead immediately
    with pytest.raises(PinsExhausted):  # rapid recycling prevented
        s.allocate(hash_token("b"))
    clk.t += 601
    assert s.allocate(hash_token("b")) == "0000"


def test_release_unknown_token_is_a_noop():
    s, _ = mem()
    assert s.release(hash_token("nope")) is None


def test_idle_identity_expires_into_cooldown():
    s, clk = mem(namespace=1, identity_ttl_s=1000, cooldown_s=500)
    s.allocate(hash_token("a"))
    clk.t += 1001
    assert s.lookup(hash_token("a")) is None  # expired credentials stop working immediately
    with pytest.raises(PinsExhausted):  # still cooling down
        s.allocate(hash_token("b"))
    clk.t += 501
    assert s.allocate(hash_token("b")) == "0000"


def test_touch_keeps_an_identity_alive():
    s, clk = mem(identity_ttl_s=1000)
    pin = s.allocate(hash_token("a"))
    for _ in range(5):
        clk.t += 600
        s.touch(pin)
    assert s.lookup(hash_token("a")) == pin  # 3000s elapsed, but never idle > 1000s


def test_unclaimed_identities_are_reclaimed_without_cooldown():
    s, clk = mem(namespace=1, unclaimed_ttl_s=300)
    s.allocate(hash_token("raced-tab"))  # never connects
    clk.t += 301
    assert s.allocate(hash_token("real")) == "0000"


def test_claimed_identities_are_not_reclaimed_as_unclaimed():
    s, clk = mem(namespace=1, unclaimed_ttl_s=300)
    pin = s.allocate(hash_token("a"))
    s.touch(pin, claim=True)
    clk.t += 301
    with pytest.raises(PinsExhausted):
        s.allocate(hash_token("b"))
