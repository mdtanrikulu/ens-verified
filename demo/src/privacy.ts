/**
 * Demo-only privacy helpers.
 *
 * The ENSIP-PRIVACY protocol primitives — salted keccak hash, redacted proof bundles,
 * the EIP-712 Disclosure signature, vendor verification — live in `@ensverify/sdk`
 * (see `sdk/src/privacy.ts`); this demo imports them from there like any integrator
 * would. What remains here is what the SDK deliberately does NOT ship:
 *
 *   - Poseidon commitments (circomlibjs is a heavy wasm dependency; the SDK takes a
 *     `computeRecordDataHash` override instead) — used for the ZK age record.
 *   - UNSALTED hashes and in-browser brute-force loops, which exist purely to
 *     demonstrate the attack that mandatory salting prevents.
 */

import { type Hex, keccak256, stringToBytes } from "viem";
import { buildPoseidon } from "circomlibjs";
import { saltedKeccakHash } from "@ensverify/sdk";

// ── Poseidon over BN254 — matches the circuit's commitment. Built once and cached. ──

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

/** keccak256(data) — the UNSALTED, brute-forceable oracle we contrast against. */
export function unsaltedKeccakHash(data: string): Hex {
  return keccak256(stringToBytes(data));
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
