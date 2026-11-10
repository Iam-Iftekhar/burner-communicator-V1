import { describe, it, expect } from "vitest";
import sodium from "libsodium-wrappers";
import { E2EESession, ProtocolError, ReplayError, type HsMsg } from "./crypto";

async function pair() {
  const a = await E2EESession.create("a");
  const b = await E2EESession.create("b");
  const commit = a.start()!;
  b.start();
  const pkb = b.handleHandshake(commit)!;
  const reveal = a.handleHandshake(pkb)!;
  b.handleHandshake(reveal);
  return { a, b };
}

const tamper = (ct: string) => {
  const bytes = sodium.from_base64(ct, sodium.base64_variants.URLSAFE_NO_PADDING);
  bytes[5] ^= 1;
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
};

describe("handshake", () => {
  it("both sides establish and show the same SAS", async () => {
    const { a, b } = await pair();
    expect(a.established && b.established).toBe(true);
    expect(a.sas).toBe(b.sas);
    expect(a.sas).toMatch(/^\d{3} \d{3}$/);
  });

  it("SAS differs across sessions", async () => {
    const sases = new Set<string>();
    for (let i = 0; i < 20; i++) sases.add((await pair()).a.sas);
    expect(sases.size).toBeGreaterThan(15);
  });

  it("a man-in-the-middle relaying with its own keys yields different SAS on each side", async () => {
    const a = await E2EESession.create("a"); // real A
    const b = await E2EESession.create("b"); // real B
    const mB = await E2EESession.create("b"); // attacker, faces A as "B"
    const mA = await E2EESession.create("a"); // attacker, faces B as "A"

    const commitA = a.start()!;
    b.start();
    mB.start();
    const commitM = mA.start()!;

    const pkbFromB = b.handleHandshake(commitM)!; // B answers the attacker's commit
    const pkbFromM = mB.handleHandshake(commitA)!; // attacker answers A's commit
    const revealA = a.handleHandshake(pkbFromM)!;
    mB.handleHandshake(revealA);
    const revealM = mA.handleHandshake(pkbFromB)!;
    b.handleHandshake(revealM);

    // Encryption "works" on each leg, which is exactly why the SAS check matters...
    expect(a.established && b.established).toBe(true);
    // ...and the SAS the two humans compare does not match (collision odds 1 in 10^6).
    expect(a.sas).not.toBe(b.sas);
  });

  it("rejects a reveal that does not match the commit", async () => {
    const a = await E2EESession.create("a");
    const b = await E2EESession.create("b");
    const commit = a.start()!;
    b.start();
    b.handleHandshake(commit);
    // Attacker substitutes different key material after seeing pkB.
    await sodium.ready;
    const b64 = (u: Uint8Array) => sodium.to_base64(u, sodium.base64_variants.URLSAFE_NO_PADDING);
    const forged: HsMsg = {
      k: "reveal",
      pk: b64(sodium.crypto_box_keypair().publicKey),
      n: b64(sodium.randombytes_buf(16)),
    };
    expect(() => b.handleHandshake(forged)).toThrow(ProtocolError);
    expect(b.established).toBe(false);
  });

  it("rejects out-of-order handshake messages", async () => {
    const b = await E2EESession.create("b");
    b.start();
    expect(() => b.handleHandshake({ k: "reveal", pk: "AAAA", n: "AAAA" })).toThrow(ProtocolError);
    const a = await E2EESession.create("a");
    expect(() => a.handleHandshake({ k: "pkb", pk: "AAAA", n: "AAAA" })).toThrow(ProtocolError);
  });

  it("rejects an all-zero (low-order) public key", async () => {
    const a = await E2EESession.create("a");
    a.start();
    const zero = sodium.to_base64(new Uint8Array(32), sodium.base64_variants.URLSAFE_NO_PADDING);
    const nonce = sodium.to_base64(new Uint8Array(16), sodium.base64_variants.URLSAFE_NO_PADDING);
    expect(() => a.handleHandshake({ k: "pkb", pk: zero, n: nonce })).toThrow(ProtocolError);
  });

  it("cannot seal or open before the handshake completes", async () => {
    const a = await E2EESession.create("a");
    expect(() => a.seal({ x: 1 })).toThrow(ProtocolError);
    expect(() => a.sas).toThrow(ProtocolError);
  });
});

describe("transport", () => {
  it("round-trips in both directions", async () => {
    const { a, b } = await pair();
    const m1 = a.seal({ t: "chat", body: "hello b" });
    expect(b.open(m1.seq, m1.ct)).toEqual({ t: "chat", body: "hello b" });
    const m2 = b.seal({ t: "chat", body: "hello a" });
    expect(a.open(m2.seq, m2.ct)).toEqual({ t: "chat", body: "hello a" });
  });

  it("rejects tampered ciphertext and does not advance state", async () => {
    const { a, b } = await pair();
    const m = a.seal({ n: 1 });
    expect(() => b.open(m.seq, tamper(m.ct))).toThrow(ProtocolError);
    expect(b.open(m.seq, m.ct)).toEqual({ n: 1 }); // genuine message still works
  });

  it("rejects replays", async () => {
    const { a, b } = await pair();
    const m = a.seal({ n: 1 });
    b.open(m.seq, m.ct);
    expect(() => b.open(m.seq, m.ct)).toThrow(ReplayError);
  });

  it("rejects stale (reordered) messages but tolerates a small forward skip", async () => {
    const { a, b } = await pair();
    const m0 = a.seal({ n: 0 });
    const m1 = a.seal({ n: 1 });
    const m2 = a.seal({ n: 2 });
    expect(b.open(m2.seq, m2.ct)).toEqual({ n: 2 }); // m0, m1 skipped (dropped)
    expect(() => b.open(m0.seq, m0.ct)).toThrow(ReplayError);
    expect(() => b.open(m1.seq, m1.ct)).toThrow(ReplayError);
  });

  it("rejects a seq far ahead (cannot be used to force unbounded work)", async () => {
    const { a, b } = await pair();
    const m = a.seal({ n: 1 });
    expect(() => b.open(10_000, m.ct)).toThrow(ProtocolError);
  });

  it("rejects reflection (a message cannot be opened by its own sender)", async () => {
    const { a } = await pair();
    const m = a.seal({ n: 1 });
    expect(() => a.open(m.seq, m.ct)).toThrow(ProtocolError);
  });

  it("a third party with different keys cannot decrypt", async () => {
    const { a } = await pair();
    const other = await pair();
    const m = a.seal({ secret: true });
    expect(() => other.b.open(m.seq, m.ct)).toThrow(ProtocolError);
  });

  it("pads to size buckets so lengths do not leak exactly", async () => {
    const { a } = await pair();
    const len = (o: unknown) => sodium.from_base64(a.seal(o).ct, sodium.base64_variants.URLSAFE_NO_PADDING).length;
    const short = len({ b: "hi" });
    const medium = len({ b: "x".repeat(100) });
    expect(short).toBe(medium); // same bucket
    expect(len({ b: "x".repeat(500) })).toBeGreaterThan(short); // next bucket
  });

  it("refuses oversized messages", async () => {
    const { a } = await pair();
    expect(() => a.seal({ b: "x".repeat(20_000) })).toThrow(ProtocolError);
  });

  it("different messages with the same content produce different ciphertext (ratchet)", async () => {
    const { a } = await pair();
    expect(a.seal({ b: "same" }).ct).not.toBe(a.seal({ b: "same" }).ct);
  });
});

describe("destruction", () => {
  it("destroy wipes secrets and disables the session", async () => {
    const { a, b } = await pair();
    const m = b.seal({ n: 1 });
    a.destroy();
    expect(a._secretsReleased()).toBe(true);
    expect(() => a.open(m.seq, m.ct)).toThrow(ProtocolError);
    expect(() => a.seal({ n: 2 })).toThrow(ProtocolError);
    expect(() => a.sas).toThrow(ProtocolError);
    a.destroy(); // idempotent
  });
});
