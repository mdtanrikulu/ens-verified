// Offline tests for the privacy module (ENSIP-PRIVACY): salted hash, redaction rules,
// disclosure signature roundtrip, canonical-signature guard. Run `npx tsc` first.
import {
  saltedKeccakHash,
  randomBytes32,
  redactProofBundle,
  parseRedactedProofBundle,
  completeRedactedBundle,
  getDisclosureTypedData,
  recoverDisclosureSigner,
  PRIVATE_RECORD_SENTINEL,
} from "./dist/index.js";
import { keccak256, concat, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
  if (!cond) failures++;
}
async function throws(name, fn) {
  try {
    await fn();
    check(name, false);
  } catch {
    check(name, true);
  }
}

// ── 1. saltedKeccakHash vs independent recomputation ─────────────────────────
const salt = "0x1111111111111111111111111111111111111111111111111111111111111111";
const email = "alice@example.com";
// Independent path: keccak256(salt-bytes ‖ utf8(data)) via concat, not encodePacked.
const expected = keccak256(concat([salt, stringToHex(email)]));
check("saltedKeccakHash matches independent keccak(salt‖utf8)", saltedKeccakHash(salt, email) === expected);
// A "0x"-prefixed *string* is treated as hex bytes, not text (documented behavior).
check(
  "saltedKeccakHash treats Hex input as raw bytes",
  saltedKeccakHash(salt, "0xdeadbeef") === keccak256(concat([salt, "0xdeadbeef"]))
);
await throws("saltedKeccakHash rejects short salt", () => saltedKeccakHash("0x1234", email));

// ── 2. redact → serialize → parse → complete roundtrip ───────────────────────
const fullBundle = {
  request: {
    node: "0x" + "ab".repeat(32),
    ensName: "alice.eth",
    resolver: "0x1111111111111111111111111111111111111111",
    recordType: "email",
    recordDataHash: expected,
    issuer: "0x2222222222222222222222222222222222222222",
    expires: 1735689600n,
    nonce: 0n,
  },
  userSignature: "0x" + "11".repeat(64) + "1b",
  contentKey: "0x" + "cd".repeat(32),
  proof: "0x" + "ef".repeat(65),
};
const redacted = redactProofBundle(fullBundle);
check("redacted version pinned", redacted.version === "1-private" && redacted.private === true);
check("redacted recordDataHash is null", redacted.request.recordDataHash === null);
const reparsed = parseRedactedProofBundle(JSON.parse(JSON.stringify(redacted)));
const completed = completeRedactedBundle(reparsed, expected);
check(
  "complete() restores the original bundle",
  JSON.stringify(completed, (_, v) => (typeof v === "bigint" ? v.toString() : v)) ===
    JSON.stringify(fullBundle, (_, v) => (typeof v === "bigint" ? v.toString() : v))
);

// ── 3. §2 rejection rules ─────────────────────────────────────────────────────
await throws("reject version '1' with private:true", () =>
  parseRedactedProofBundle({ ...redacted, version: "1" })
);
await throws("reject '1-private' without private:true", () =>
  parseRedactedProofBundle({ ...redacted, private: false })
);
await throws("reject non-null recordDataHash", () =>
  parseRedactedProofBundle({
    ...redacted,
    request: { ...redacted.request, recordDataHash: expected },
  })
);
await throws("reject missing recordDataHash key", () => {
  const { recordDataHash, ...rest } = redacted.request;
  return parseRedactedProofBundle({ ...redacted, request: rest });
});
await throws("reject non-decimal expires", () =>
  parseRedactedProofBundle({
    ...redacted,
    request: { ...redacted.request, expires: "0x10" },
  })
);

// ── 4. Disclosure EIP-712 sign/recover roundtrip (offline) ───────────────────
const account = privateKeyToAccount("0x" + "00".repeat(31) + "01");
const controller = "0x4242424242424242424242424242424242424242";
const disclosure = {
  node: "0x" + "ab".repeat(32),
  issuer: "0x2222222222222222222222222222222222222222",
  recordType: "email",
  nonce: randomBytes32(),
  vendor: "0x0000000000000000000000000000000000000000",
  vendorIdentity: "https://vendor.example.com",
  expires: 0n,
};
const typed = getDisclosureTypedData(disclosure, controller, 1);
check(
  "typed data includes vendorIdentity",
  typed.types.Disclosure.some((f) => f.name === "vendorIdentity" && f.type === "string")
);
const sig = await account.signTypedData(typed);
const signer = await recoverDisclosureSigner(disclosure, sig, controller, 1);
check("disclosure signer roundtrip", signer.toLowerCase() === account.address.toLowerCase());

// Tampered struct must recover a different signer.
const other = await recoverDisclosureSigner(
  { ...disclosure, vendorIdentity: "https://evil.example.com" },
  sig,
  controller,
  1
);
check("vendorIdentity is signature-bound", other.toLowerCase() !== account.address.toLowerCase());

// ── 5. Canonical-signature guard (L-5) ────────────────────────────────────────
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const r = sig.slice(2, 66);
const s = BigInt("0x" + sig.slice(66, 130));
const v = parseInt(sig.slice(130, 132), 16);
const highS = ((N - s).toString(16).padStart(64, "0"));
const flippedV = (v === 27 ? 28 : 27).toString(16).padStart(2, "0");
const malleated = "0x" + r + highS + flippedV;
await throws("high-s signature rejected", () =>
  recoverDisclosureSigner(disclosure, malleated, controller, 1)
);
await throws("truncated signature rejected", () =>
  recoverDisclosureSigner(disclosure, sig.slice(0, 100), controller, 1)
);

// ── 6. serialize/parse roundtrip (base §8 document) ──────────────────────────
const { serializeProofBundle, parseProofBundle } = await import("./dist/index.js");
const roundtripped = parseProofBundle(JSON.parse(serializeProofBundle(fullBundle)));
check(
  "serializeProofBundle ∘ parseProofBundle is identity",
  JSON.stringify(roundtripped, (_, v) => (typeof v === "bigint" ? v.toString() : v)) ===
    JSON.stringify(fullBundle, (_, v) => (typeof v === "bigint" ? v.toString() : v))
);

// ── 7. Sentinel constant ──────────────────────────────────────────────────────
check("sentinel is bytes32(0)", PRIVATE_RECORD_SENTINEL === "0x" + "0".repeat(64));

console.log(failures === 0 ? "\nAll privacy tests passed" : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
