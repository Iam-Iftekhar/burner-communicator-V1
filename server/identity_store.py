"""Identity + PIN allocation store.

The PIN is a public routing label. Authority comes from a 256-bit recovery token that the client
holds (as an HttpOnly cookie); the store keeps only SHA-256(token). A token is high-entropy, so a
fast hash is sufficient (a slow KDF adds nothing against a 256-bit random secret).

`IdentityStore` is the seam for a later move to Redis/Postgres: the hub and HTTP layer only use
the methods on the protocol below.

Atomicity: every mutation runs in `BEGIN IMMEDIATE`, which takes SQLite's write lock before any
read, so two concurrent allocations cannot both pick the same PIN. `pin` is also the PRIMARY KEY,
so a bug in the allocation logic would fail loudly with an IntegrityError instead of silently
double-assigning.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Callable, Iterator, Protocol


class PinsExhausted(Exception):
    """Every PIN is assigned or cooling down."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class IdentityStore(Protocol):
    def allocate(self, token_hash: str) -> str: ...
    def lookup(self, token_hash: str) -> str | None: ...
    def touch(self, pin: str, claim: bool = False) -> None: ...
    def release(self, token_hash: str) -> str | None: ...
    def purge(self) -> None: ...
    def count(self) -> int: ...


SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    pin        TEXT PRIMARY KEY,             -- always 4 chars, leading zeros preserved
    token_hash TEXT NOT NULL UNIQUE,
    created    REAL NOT NULL,
    last_seen  REAL NOT NULL,
    claimed    INTEGER NOT NULL DEFAULT 0    -- 1 once a websocket has authenticated as this identity
);
CREATE TABLE IF NOT EXISTS cooldown (
    pin   TEXT PRIMARY KEY,
    until REAL NOT NULL
);
"""


class SqliteIdentityStore:
    def __init__(
        self,
        path: str,
        *,
        namespace: int = 10_000,
        identity_ttl_s: float = 30 * 86400,
        cooldown_s: float = 600,
        unclaimed_ttl_s: float = 300,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not 1 <= namespace <= 10_000:
            raise ValueError("namespace must be 1..10000")
        self.path = path
        self.namespace = namespace
        self.identity_ttl_s = identity_ttl_s
        self.cooldown_s = cooldown_s
        self.unclaimed_ttl_s = unclaimed_ttl_s
        self.clock = clock
        self._lock = threading.Lock()
        self._mem: sqlite3.Connection | None = None
        if path == ":memory:":
            # A private in-memory DB lives and dies with one connection, so share it (serialised by a lock).
            self._mem = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        else:
            con = sqlite3.connect(path, timeout=15, isolation_level=None)
            con.execute("PRAGMA journal_mode=WAL")
            con.close()
        with self._txn(write=True) as con:
            for stmt in SCHEMA.split(";"):
                if stmt.strip():
                    con.execute(stmt)

    # ---- plumbing ----

    @contextmanager
    def _txn(self, write: bool) -> Iterator[sqlite3.Connection]:
        if self._mem is not None:
            self._lock.acquire()
            con = self._mem
        else:
            con = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        try:
            con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield con
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        finally:
            if self._mem is not None:
                self._lock.release()
            else:
                con.close()

    def _purge(self, con: sqlite3.Connection, now: float) -> None:
        # Idle identities are released into cooldown so their PIN is not instantly reassigned.
        stale = con.execute("SELECT pin FROM identities WHERE last_seen < ?", (now - self.identity_ttl_s,)).fetchall()
        for (pin,) in stale:
            con.execute("INSERT OR REPLACE INTO cooldown(pin, until) VALUES (?, ?)", (pin, now + self.cooldown_s))
            con.execute("DELETE FROM identities WHERE pin = ?", (pin,))
        # Identities that never connected were never shown to anyone: free them without cooldown.
        # (Happens when two tabs race to register and one cookie overwrites the other.)
        con.execute("DELETE FROM identities WHERE claimed = 0 AND created < ?", (now - self.unclaimed_ttl_s,))
        con.execute("DELETE FROM cooldown WHERE until <= ?", (now,))

    # ---- API ----

    def allocate(self, token_hash: str) -> str:
        now = self.clock()
        with self._txn(write=True) as con:
            self._purge(con, now)
            used = {r[0] for r in con.execute("SELECT pin FROM identities")}
            used |= {r[0] for r in con.execute("SELECT pin FROM cooldown")}
            free = [f"{n:04d}" for n in range(self.namespace) if f"{n:04d}" not in used]
            pin = secrets.choice(free) if free else None  # random, so PINs are not sequential
            if pin is not None:
                con.execute(
                    "INSERT INTO identities(pin, token_hash, created, last_seen, claimed) VALUES (?, ?, ?, ?, 0)",
                    (pin, token_hash, now, now),
                )
        # Raise only after COMMIT: raising inside the transaction would roll back the purge above,
        # silently undoing expiry/cooldown bookkeeping every time the namespace is full.
        if pin is None:
            raise PinsExhausted()
        return pin

    def lookup(self, token_hash: str) -> str | None:
        now = self.clock()
        with self._txn(write=False) as con:
            row = con.execute(
                "SELECT pin FROM identities WHERE token_hash = ? AND last_seen >= ?",
                (token_hash, now - self.identity_ttl_s),
            ).fetchone()
        return row[0] if row else None

    def touch(self, pin: str, claim: bool = False) -> None:
        with self._txn(write=True) as con:
            con.execute(
                "UPDATE identities SET last_seen = ?, claimed = CASE WHEN ? THEN 1 ELSE claimed END WHERE pin = ?",
                (self.clock(), 1 if claim else 0, pin),
            )

    def release(self, token_hash: str) -> str | None:
        now = self.clock()
        with self._txn(write=True) as con:
            row = con.execute("SELECT pin FROM identities WHERE token_hash = ?", (token_hash,)).fetchone()
            if not row:
                return None
            pin = row[0]
            con.execute("DELETE FROM identities WHERE pin = ?", (pin,))
            con.execute("INSERT OR REPLACE INTO cooldown(pin, until) VALUES (?, ?)", (pin, now + self.cooldown_s))
            return pin

    def purge(self) -> None:
        with self._txn(write=True) as con:
            self._purge(con, self.clock())

    def count(self) -> int:
        with self._txn(write=False) as con:
            return con.execute("SELECT COUNT(*) FROM identities").fetchone()[0]
