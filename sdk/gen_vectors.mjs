// Generates the signed EIP-712 round-trip test vectors published in ENSIP.md §5 and
// ENSIP-PRIVACY.md §5 (IMPROVEMENTS #3). Deterministic: fixed private key, RFC-6979
// signatures (noble-curves via viem). Cross-checks every manual hash against viem's
// hashTypedData before printing. Run `npx tsc` first.
import {
  keccak256,
  encodeAbiParameters,
  concat,
  stringToHex,
  hashTypedData,
  hashDomain,
  namehash,
  recoverAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { computeContentKey, saltedKeccakHash } from "./dist/index.js";

const PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000001";
const account = privateKeyToAccount(PRIVATE_KEY);
const CONTROLLER = "0x4242424242424242424242424242424242424242";
const CHAIN_ID = 1;

const assert = (name, cond) => {
  if (!cond) throw new Error(`self-check failed: ${name}`);
};

// ── Base spec vector: RecordRequest ──────────────────────────────────────────
const request = {
  node: namehash("alice.eth"),
  ensName: "alice.eth",
  resolver: "0x1111111111111111111111111111111111111111",
  recordType: "identity",
  recordDataHash: keccak256(stringToHex("credential-payload")),
  issuer: "0x2222222222222222222222222222222222222222",
  expires: 1735689600n,
  nonce: 0n,
};

const RECORD_REQUEST_TYPE =
  "RecordRequest(bytes32 node,string ensName,address resolver,string recordType,bytes32 recordDataHash,address issuer,uint64 expires,uint256 nonce)";
const recordTypehash = keccak256(stringToHex(RECORD_REQUEST_TYPE));

const baseDomain = {
  name: "ENS Verifiable Records",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: CONTROLLER,
};
const baseTypes = {
  RecordRequest: [
    { name: "node", type: "bytes32" },
    { name: "ensName", type: "string" },
    { name: "resolver", type: "address" },
    { name: "recordType", type: "string" },
    { name: "recordDataHash", type: "bytes32" },
    { name: "issuer", type: "address" },
    { name: "expires", type: "uint64" },
    { name: "nonce", type: "uint256" },
  ],
};

const baseDomainSeparator = hashDomain({
  domain: baseDomain,
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ],
  },
});

const baseStructHash = keccak256(
  encodeAbiParameters(
    [
      { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "address" },
      { type: "bytes32" }, { type: "bytes32" }, { type: "address" }, { type: "uint64" },
      { type: "uint256" },
    ],
    [
      recordTypehash,
      request.node,
      keccak256(stringToHex(request.ensName)),
      request.resolver,
      keccak256(stringToHex(request.recordType)),
      request.recordDataHash,
      request.issuer,
      request.expires,
      request.nonce,
    ]
  )
);
const baseDigest = keccak256(concat(["0x1901", baseDomainSeparator, baseStructHash]));

// Self-check the manual computation against viem's implementation of EIP-712.
const baseDigestViem = hashTypedData({
  domain: baseDomain,
  types: baseTypes,
  primaryType: "RecordRequest",
  message: request,
});
assert("base digest matches hashTypedData", baseDigest === baseDigestViem);

const baseSignature = await account.signTypedData({
  domain: baseDomain,
  types: baseTypes,
  primaryType: "RecordRequest",
  message: request,
});
assert(
  "base signature recovers",
  (await recoverAddress({ hash: baseDigest, signature: baseSignature })).toLowerCase() ===
    account.address.toLowerCase()
);

const contentKey = computeContentKey(request, baseSignature);

// ── Privacy spec vector: salted hash + Disclosure ────────────────────────────
const salt = "0x1111111111111111111111111111111111111111111111111111111111111111";
const data = "alice@example.com";
const privRecordDataHash = saltedKeccakHash(salt, data);

const disclosure = {
  node: namehash("alice.eth"),
  issuer: "0x2222222222222222222222222222222222222222",
  recordType: "email",
  nonce: "0x3333333333333333333333333333333333333333333333333333333333333333",
  vendor: "0x0000000000000000000000000000000000000000",
  vendorIdentity: "https://vendor.example.com",
  expires: 0n,
};

const DISCLOSURE_TYPE =
  "Disclosure(bytes32 node,address issuer,string recordType,bytes32 nonce,address vendor,string vendorIdentity,uint64 expires)";
const disclosureTypehash = keccak256(stringToHex(DISCLOSURE_TYPE));

const privDomain = {
  name: "ENS Selective Disclosure",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: CONTROLLER,
};
const privTypes = {
  Disclosure: [
    { name: "node", type: "bytes32" },
    { name: "issuer", type: "address" },
    { name: "recordType", type: "string" },
    { name: "nonce", type: "bytes32" },
    { name: "vendor", type: "address" },
    { name: "vendorIdentity", type: "string" },
    { name: "expires", type: "uint64" },
  ],
};

const privDomainSeparator = hashDomain({
  domain: privDomain,
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ],
  },
});
const privStructHash = keccak256(
  encodeAbiParameters(
    [
      { type: "bytes32" }, { type: "bytes32" }, { type: "address" }, { type: "bytes32" },
      { type: "bytes32" }, { type: "address" }, { type: "bytes32" }, { type: "uint64" },
    ],
    [
      disclosureTypehash,
      disclosure.node,
      disclosure.issuer,
      keccak256(stringToHex(disclosure.recordType)),
      disclosure.nonce,
      disclosure.vendor,
      keccak256(stringToHex(disclosure.vendorIdentity)),
      disclosure.expires,
    ]
  )
);
const privDigest = keccak256(concat(["0x1901", privDomainSeparator, privStructHash]));
const privDigestViem = hashTypedData({
  domain: privDomain,
  types: privTypes,
  primaryType: "Disclosure",
  message: disclosure,
});
assert("disclosure digest matches hashTypedData", privDigest === privDigestViem);

const disclosureSignature = await account.signTypedData({
  domain: privDomain,
  types: privTypes,
  primaryType: "Disclosure",
  message: disclosure,
});
assert(
  "disclosure signature recovers",
  (await recoverAddress({ hash: privDigest, signature: disclosureSignature })).toLowerCase() ===
    account.address.toLowerCase()
);

// ── Output ────────────────────────────────────────────────────────────────────
console.log(JSON.stringify({
  signer: { privateKey: PRIVATE_KEY, address: account.address },
  base: {
    domain: baseDomain,
    request: { ...request, expires: request.expires.toString(), nonce: request.nonce.toString() },
    recordRequestTypehash: recordTypehash,
    domainSeparator: baseDomainSeparator,
    structHash: baseStructHash,
    digest: baseDigest,
    signature: baseSignature,
    contentKey,
  },
  privacy: {
    salt, data,
    recordDataHash: privRecordDataHash,
    domain: privDomain,
    disclosure: { ...disclosure, expires: disclosure.expires.toString() },
    disclosureTypehash,
    domainSeparator: privDomainSeparator,
    structHash: privStructHash,
    digest: privDigest,
    signature: disclosureSignature,
  },
}, null, 2));
