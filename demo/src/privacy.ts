/**
 * ENSIP-PRIVACY — Selective Disclosure primitives (browser).
 *
 * Everything the extension needs is client-side crypto plus the base on-chain
 * verification the demo already performs:
 *
 *   - salted recordDataHash   (Section 1)         → keccak256(salt‖data) or Poseidon(value, salt)
 *   - redacted proof bundle    (Section 2)         → recordDataHash omitted, version "1-private"
 *   - EIP-712 disclosure sig    (Section 5)         → binds node/issuer/type/nonce/vendor/expires
 *   - vendor verification       (Section 4, step 8) → reconstruct recordDataHash, run base §7 flow
 *
 * The brute-force helpers demonstrate the motivation: an UNSALTED low-entropy
 * commitment (keccak or Poseidon) is an offline oracle, crackable in-browser;
 * the salted commitment is not.
 */

import {
  type Address,
  type Hex,
  encodePacked,
  keccak256,
  toBytes,
  toHex,
} from "viem";
import { buildPoseidon } from "circomlibjs";
import type { ProofBundle, RecordRequest } from "@ensverify/sdk";

// ── Salted recordDataHash (Section 1) ────────────────────────────────────────

/** keccak256(abi.encodePacked(salt, data)) — the private hash for non-ZK records (e.g. email). */
export function saltedKeccakHash(salt: Hex, data: string): Hex {
  return keccak256(encodePacked(["bytes32", "bytes"], [salt, toHex(toBytes(data))]));
}

/** keccak256(data) — the UNSALTED, brute-forceable oracle we contrast against. */
export function unsaltedKeccakHash(data: string): Hex {
  return keccak256(toHex(toBytes(data)));
}

// Poseidon over BN254 — matches the circuit's commitment. Built once and cached.
let _poseidon: Awaited<ReturnType<typeof buildPoseidon>> | null = null;

export async function getPoseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

function fieldToHex(decimal: string): Hex {
  return ("0x" + BigInt(decimal).toString(16).padStart(64, "0")) as Hex;
}

/** Poseidon(value, salt) as bytes32 — identical to the salted age circuit's `birthdayHash`. */
export async function saltedPoseidonHash(value: bigint, salt: bigint): Promise<Hex> {
  const p = await getPoseidon();
  return fieldToHex(p.F.toString(p([value, salt])));
}

/** Poseidon(value) — the UNSALTED commitment an attacker would brute-force. */
export async function unsaltedPoseidonHash(value: bigint): Promise<Hex> {
  const p = await getPoseidon();
  return fieldToHex(p.F.toString(p([value])));
}

// ── Redacted proof bundle (Section 2) ────────────────────────────────────────

export interface RedactedBundle {
  version: "1-private";
  private: true;
  request: {
    node: Hex;
    ensName: string;
    resolver: Address;
    recordType: string;
    recordDataHash: null;
    issuer: Address;
    expires: string;
    nonce: string;
  };
  userSignature: Hex;
  contentKey: Hex;
  proof: Hex;
}

/** Produces the public, redacted bundle: recordDataHash stripped, version pinned to "1-private". */
export function redactBundle(bundle: ProofBundle): RedactedBundle {
  return {
    version: "1-private",
    private: true,
    request: {
      node: bundle.request.node,
      ensName: bundle.request.ensName,
      resolver: bundle.request.resolver,
      recordType: bundle.request.recordType,
      recordDataHash: null,
      issuer: bundle.request.issuer,
      expires: bundle.request.expires.toString(),
      nonce: bundle.request.nonce.toString(),
    },
    userSignature: bundle.userSignature,
    contentKey: bundle.contentKey,
    proof: bundle.proof,
  };
}

/** Applies the Section 2 rejection rules to an arbitrary fetched object. Returns null if invalid. */
export function parseRedactedBundle(data: any): RedactedBundle | null {
  if (data?.private !== true) return null; // not a private bundle
  if (data.version !== "1-private") return null; // §2: private ⇒ version must be "1-private"
  if (data.recordDataHash != null || data.request?.recordDataHash != null) return null; // §2: must be redacted
  if (!data.request || !data.userSignature || !data.contentKey || !data.proof) return null;
  return data as RedactedBundle;
}

/**
 * Vendor step 7: complete the redacted bundle by inserting the recordDataHash the vendor
 * reconstructed from the disclosed (salt, data). The result is a full base-spec ProofBundle
 * ready for the standard §7 verification pipeline.
 */
export function completeBundle(
  redacted: RedactedBundle,
  recordDataHash: Hex
): ProofBundle {
  const request: RecordRequest = {
    node: redacted.request.node,
    ensName: redacted.request.ensName,
    resolver: redacted.request.resolver,
    recordType: redacted.request.recordType,
    recordDataHash,
    issuer: redacted.request.issuer,
    expires: BigInt(redacted.request.expires),
    nonce: BigInt(redacted.request.nonce),
  };
  return {
    request,
    userSignature: redacted.userSignature,
    contentKey: redacted.contentKey,
    proof: redacted.proof,
  };
}

// ── Disclosure signature (Section 5, EIP-712) ────────────────────────────────

export interface DisclosureParams {
  node: Hex;
  issuer: Address;
  recordType: string;
  nonce: Hex; // vendor-issued, 32 bytes
  vendor: Address; // address(0) if the vendor does not authenticate via a wallet
  expires: bigint; // 0 = no expiry
}

/** EIP-712 typed data for the `Disclosure` struct (Section 5). */
export function getDisclosureTypedData(
  params: DisclosureParams,
  controllerAddress: Address,
  chainId: number
) {
  return {
    domain: {
      name: "ENS Selective Disclosure",
      version: "1",
      chainId: BigInt(chainId),
      verifyingContract: controllerAddress,
    },
    types: {
      Disclosure: [
        { name: "node", type: "bytes32" },
        { name: "issuer", type: "address" },
        { name: "recordType", type: "string" },
        { name: "nonce", type: "bytes32" },
        { name: "vendor", type: "address" },
        { name: "expires", type: "uint64" },
      ],
    },
    primaryType: "Disclosure" as const,
    message: {
      node: params.node,
      issuer: params.issuer,
      recordType: params.recordType,
      nonce: params.nonce,
      vendor: params.vendor,
      expires: params.expires,
    },
  };
}

/** A cryptographically-random 32-byte vendor nonce (Section 4, step 1). */
export function randomNonce(): Hex {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return ("0x" +
    Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")) as Hex;
}

// ── Brute-force demonstration (Security Considerations) ───────────────────────

export interface BruteForceResult {
  cracked: string | null;
  tried: number;
  elapsedMs: number;
}

/**
 * Tests candidate emails against a target keccak hash, chunked so the UI stays responsive.
 * With `salt` provided, tests keccak256(salt‖candidate); without, keccak256(candidate).
 */
export async function bruteForceEmail(
  targetHash: Hex,
  candidates: string[],
  opts: { salt?: Hex; onProgress?: (tried: number) => void } = {}
): Promise<BruteForceResult> {
  const start = performance.now();
  let tried = 0;
  const CHUNK = 500;
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    const h = opts.salt ? saltedKeccakHash(opts.salt, c) : unsaltedKeccakHash(c);
    tried++;
    if (h === targetHash) {
      return { cracked: c, tried, elapsedMs: performance.now() - start };
    }
    if (tried % CHUNK === 0) {
      opts.onProgress?.(tried);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  return { cracked: null, tried, elapsedMs: performance.now() - start };
}

export interface BirthdayBruteForceResult extends BruteForceResult {
  crackedUnix: number | null;
}

/**
 * Enumerates candidate birthdays (one per day) against a target Poseidon commitment.
 * With `salt` provided, tests Poseidon(day, salt); without, Poseidon(day) — the unsalted
 * commitment is the crackable one.
 */
export async function bruteForceBirthday(
  targetHash: Hex,
  range: { startUnix: number; endUnix: number },
  opts: { salt?: bigint; onProgress?: (tried: number, total: number) => void } = {}
): Promise<BirthdayBruteForceResult> {
  const p = await getPoseidon();
  const start = performance.now();
  const DAY = 86_400;
  const total = Math.floor((range.endUnix - range.startUnix) / DAY) + 1;
  let tried = 0;
  const CHUNK = 750;
  for (let t = range.startUnix; t <= range.endUnix; t += DAY) {
    const h =
      opts.salt !== undefined
        ? fieldToHex(p.F.toString(p([BigInt(t), opts.salt])))
        : fieldToHex(p.F.toString(p([BigInt(t)])));
    tried++;
    if (h === targetHash) {
      return { cracked: String(t), crackedUnix: t, tried, elapsedMs: performance.now() - start };
    }
    if (tried % CHUNK === 0) {
      opts.onProgress?.(tried, total);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  return { cracked: null, crackedUnix: null, tried, elapsedMs: performance.now() - start };
}

/**
 * Builds a realistic candidate email list (common local-parts × domains) with `include`
 * guaranteed present, so the unsalted brute-force reliably lands on the target.
 */
export function buildEmailCandidates(include: string): string[] {
  const locals = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "ivan",
    "judy", "mallory", "olivia", "peggy", "trent", "victor", "walter", "john",
    "jane", "mike", "sarah", "david", "emma", "chris", "anna", "james", "mary",
    "robert", "linda", "michael", "patricia",
  ];
  const domains = [
    "example.com", "gmail.com", "outlook.com", "proton.me", "yahoo.com",
    "icloud.com", "ens.domains", "company.io", "mail.com", "fastmail.com",
  ];
  const set = new Set<string>();
  for (const l of locals) for (const d of domains) set.add(`${l}@${d}`);
  set.add(include);
  return Array.from(set);
}
