/**
 * Phase 0 spike: ephemeral E2EE session (transport-agnostic, no DOM, no network).
 *
 * Construction (all primitives from libsodium; NO custom primitives):
 *   1. Commit-then-reveal handshake (ZRTP-style) so a MITM cannot grind keys to
 *      force matching Short Authentication Strings:
 *        A -> B : commit = H(domain | pkA | nA)
 *        B -> A : pkB, nB
 *        A -> B : pkA, nA          (B checks it against the commit)
 *   2. dh      = X25519(sk_self, pk_peer)
 *      th      = H(domain | pkA | pkB | nA | nB)            transcript hash
 *      master  = BLAKE2b(dh, key = th)                      binds keys to transcript
 *      K(A->B) = KDF(master, id 1), K(B->A) = KDF(master, id 2)
 *   3. SAS     = 6 digits derived from th. Users compare it out of band.
 *   4. Transport: per-message key from a hash chain (old chain key is zeroized
 *      after each message), XChaCha20-Poly1305, AAD = direction | seq,
 *      plaintext padded to size buckets.
 *
 * Properties claimed (and nothing more):
 *   - Confidentiality + integrity of messages (AEAD).
 *   - Peer authentication ONLY if both users compare the SAS and it matches.
 *   - Forward secrecy: ephemeral keys + per-message chain-key deletion.
 *   - Replay / reorder rejection via strictly increasing seq.
 *   - NOT claimed: post-compromise security, deniability.
 *
 * SPIKE CAVEAT: this composes libsodium primitives into a protocol. That is a
 * custom *protocol* even though the primitives are standard. Before production,
 * replace with a reviewed protocol implementation (e.g. a Noise library) or get
 * this construction independently reviewed.
 */
import sodium from "libsodium-wrappers";

export type Role = "a" | "b";

export type HsMsg =
  | { k: "commit"; c: string }
  | { k: "pkb"; pk: string; n: string }
  | { k: "reveal"; pk: string; n: string };

export class ProtocolError extends Error {}
export class ReplayError extends ProtocolError {}

const DOMAIN = "ephemeral/phase0/v0";
const KDF_CTX = "ephmsg00"; // exactly 8 bytes
export const BUCKETS = [256, 1024, 4096, 16384] as const;
const MAX_SKIP = 32;
const NONCE_LEN = 16;

const enc = new TextEncoder();
const dec = new TextDecoder();

const b64 = (u: Uint8Array) => sodium.to_base64(u, sodium.base64_variants.URLSAFE_NO_PADDING);
const unb64 = (s: string) => sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && sodium.memcmp(a, b);
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

type State = "init" | "await_pkb" | "await_commit" | "await_reveal" | "established" | "destroyed";

export class E2EESession {
  private state: State = "init";
  private sk: Uint8Array | null = null;
  private pkSelf: Uint8Array | null = null;
  private nSelf: Uint8Array | null = null;
  private peerCommit: Uint8Array | null = null;
  private pkPeer: Uint8Array | null = null;
  private nPeer: Uint8Array | null = null;

  private sendCk: Uint8Array | null = null;
  private recvCk: Uint8Array | null = null;
  private sendSeq = 0;
  private recvSeq = 0;
  private _sas: string | null = null;

  private constructor(readonly role: Role) {}

  static async create(role: Role): Promise<E2EESession> {
    await sodium.ready;
    return new E2EESession(role);
  }

  get established(): boolean {
    return this.state === "established";
  }

  /** 6-digit Short Authentication String, e.g. "123 456". Only after handshake. */
  get sas(): string {
    if (!this._sas) throw new ProtocolError("SAS not available before handshake completes");
    return this._sas;
  }

  /** Role "a" calls this to produce the first handshake message. Role "b" returns null. */
  start(): HsMsg | null {
    if (this.state !== "init") throw new ProtocolError("already started");
    this.genEphemeral();
    if (this.role === "b") {
      this.state = "await_commit";
      return null;
    }
    const commit = sodium.crypto_generichash(32, concat(enc.encode(DOMAIN + "/commit"), this.pkSelf!, this.nSelf!));
    this.state = "await_pkb";
    return { k: "commit", c: b64(commit) };
  }

  /** Feed a peer handshake message; returns the reply to send (or null). */
  handleHandshake(m: HsMsg): HsMsg | null {
    switch (this.state) {
      case "await_pkb": {
        if (this.role !== "a" || m.k !== "pkb") throw new ProtocolError("unexpected handshake message");
        this.pkPeer = this.checkPk(m.pk);
        this.nPeer = this.checkNonce(m.n);
        this.derive(this.pkSelf!, this.pkPeer, this.nSelf!, this.nPeer);
        return { k: "reveal", pk: b64(this.pkSelf!), n: b64(this.nSelf!) };
      }
      case "await_commit": {
        if (this.role !== "b" || m.k !== "commit") throw new ProtocolError("unexpected handshake message");
        const c = unb64(m.c);
        if (c.length !== 32) throw new ProtocolError("bad commit");
        this.peerCommit = c;
        this.state = "await_reveal";
        return { k: "pkb", pk: b64(this.pkSelf!), n: b64(this.nSelf!) };
      }
      case "await_reveal": {
        if (this.role !== "b" || m.k !== "reveal") throw new ProtocolError("unexpected handshake message");
        const pkA = this.checkPk(m.pk);
        const nA = this.checkNonce(m.n);
        const expect = sodium.crypto_generichash(32, concat(enc.encode(DOMAIN + "/commit"), pkA, nA));
        if (!eq(expect, this.peerCommit!)) throw new ProtocolError("reveal does not match commit");
        this.pkPeer = pkA;
        this.nPeer = nA;
        this.derive(pkA, this.pkSelf!, nA, this.nSelf!);
        return null;
      }
      default:
        throw new ProtocolError(`handshake message in state ${this.state}`);
    }
  }

  /** Encrypt an application object. Returns the opaque envelope fields the server relays. */
  seal(obj: unknown): { seq: number; ct: string } {
    this.requireEstablished();
    const plain = enc.encode(JSON.stringify(obj));
    const bucket = BUCKETS.find((b) => b >= plain.length + 1);
    if (!bucket) throw new ProtocolError("message too large");
    const padded = sodium.pad(plain, bucket);
    const seq = this.sendSeq++; // chain and seq advance together, before any fallible step
    const mk = this.stepChain();
    try {
      const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        padded,
        this.aad(this.role, seq),
        null,
        this.nonce(seq),
        mk,
      );
      return { seq, ct: b64(ct) };
    } finally {
      sodium.memzero(mk);
      sodium.memzero(plain);
      sodium.memzero(padded);
    }
  }

  /** Decrypt an envelope from the peer. Throws on tamper, replay, reorder, or reflection. */
  open<T = unknown>(seq: number, ctB64: string): T {
    this.requireEstablished();
    if (!Number.isInteger(seq) || seq < 0 || seq > 0xffffffff) throw new ProtocolError("bad seq");
    if (seq < this.recvSeq) throw new ReplayError("replayed or stale message");
    if (seq > this.recvSeq + MAX_SKIP) throw new ProtocolError("seq too far ahead");

    // Work on a copy so a forged message cannot advance our state.
    let ck: Uint8Array = this.recvCk!.slice();
    let mk: Uint8Array | null = null;
    try {
      for (let i = this.recvSeq; i <= seq; i++) {
        const next = this.deriveStep(ck);
        sodium.memzero(ck);
        ck = next.ck;
        if (mk) sodium.memzero(mk);
        mk = next.mk;
      }
      const peerRole: Role = this.role === "a" ? "b" : "a";
      let padded: Uint8Array;
      try {
        padded = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          unb64(ctB64),
          this.aad(peerRole, seq),
          this.nonce(seq),
          mk!,
        );
      } catch {
        throw new ProtocolError("decryption failed");
      }
      if (!(BUCKETS as readonly number[]).includes(padded.length)) throw new ProtocolError("bad padding bucket");
      const plain = sodium.unpad(padded, padded.length);
      const obj = JSON.parse(dec.decode(plain)) as T;
      sodium.memzero(padded);
      // Commit state only after authentication succeeded.
      sodium.memzero(this.recvCk!);
      this.recvCk = ck;
      ck = new Uint8Array(0);
      this.recvSeq = seq + 1;
      return obj;
    } finally {
      sodium.memzero(ck);
      if (mk) sodium.memzero(mk);
    }
  }

  /** Zeroize all key material. Idempotent. JS cannot guarantee wiping of copies the engine made. */
  destroy(): void {
    for (const k of [this.sk, this.sendCk, this.recvCk, this.nSelf, this.pkSelf, this.pkPeer, this.nPeer, this.peerCommit]) {
      if (k) sodium.memzero(k);
    }
    this.sk = this.sendCk = this.recvCk = null;
    this.nSelf = this.pkSelf = this.pkPeer = this.nPeer = this.peerCommit = null;
    this._sas = null;
    this.state = "destroyed";
  }

  /** Test helper: are all secret buffers wiped/released? */
  _secretsReleased(): boolean {
    return !this.sk && !this.sendCk && !this.recvCk && this.state === "destroyed";
  }

  // ---- internals ----

  private genEphemeral() {
    const kp = sodium.crypto_box_keypair(); // X25519
    this.sk = kp.privateKey;
    this.pkSelf = kp.publicKey;
    this.nSelf = sodium.randombytes_buf(NONCE_LEN);
  }

  private checkPk(s: string): Uint8Array {
    const pk = unb64(s);
    if (pk.length !== 32) throw new ProtocolError("bad public key length");
    return pk;
  }

  private checkNonce(s: string): Uint8Array {
    const n = unb64(s);
    if (n.length !== NONCE_LEN) throw new ProtocolError("bad nonce length");
    return n;
  }

  private derive(pkA: Uint8Array, pkB: Uint8Array, nA: Uint8Array, nB: Uint8Array) {
    let dh: Uint8Array;
    try {
      dh = sodium.crypto_scalarmult(this.sk!, this.pkPeer!); // throws on all-zero output (low-order point)
    } catch {
      throw new ProtocolError("invalid peer public key");
    }
    const th = sodium.crypto_generichash(32, concat(enc.encode(DOMAIN + "/transcript"), pkA, pkB, nA, nB));
    const master = sodium.crypto_generichash(32, dh, th);
    const kAB = sodium.crypto_kdf_derive_from_key(32, 1, KDF_CTX, master);
    const kBA = sodium.crypto_kdf_derive_from_key(32, 2, KDF_CTX, master);
    this.sendCk = this.role === "a" ? kAB : kBA;
    this.recvCk = this.role === "a" ? kBA : kAB;

    const sasBytes = sodium.crypto_generichash(4, concat(enc.encode(DOMAIN + "/sas"), th));
    const n = new DataView(sasBytes.buffer, sasBytes.byteOffset, 4).getUint32(0, false) % 1_000_000;
    const s = n.toString().padStart(6, "0");
    this._sas = `${s.slice(0, 3)} ${s.slice(3)}`;

    sodium.memzero(dh);
    sodium.memzero(master);
    sodium.memzero(th);
    sodium.memzero(this.sk!); // ephemeral private key no longer needed
    this.sk = null;
    this.state = "established";
  }

  private deriveStep(ck: Uint8Array): { mk: Uint8Array; ck: Uint8Array } {
    return {
      mk: sodium.crypto_generichash(32, enc.encode("mk"), ck),
      ck: sodium.crypto_generichash(32, enc.encode("ck"), ck),
    };
  }

  private stepChain(): Uint8Array {
    const next = this.deriveStep(this.sendCk!);
    sodium.memzero(this.sendCk!);
    this.sendCk = next.ck;
    return next.mk;
  }

  private aad(role: Role, seq: number): Uint8Array {
    return concat(enc.encode("v0"), new Uint8Array([role === "a" ? 0 : 1]), u32le(seq));
  }

  private nonce(seq: number): Uint8Array {
    const n = new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    n.set(u32le(seq), 0);
    return n;
  }

  private requireEstablished() {
    if (this.state !== "established") throw new ProtocolError(`session not established (${this.state})`);
  }
}
