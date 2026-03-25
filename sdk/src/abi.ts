// ─── VerifiableRecordController ABI ─────────────────────────────────────────

export const VerifiableRecordControllerABI = [
  {
    type: "function",
    name: "issueRecord",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "node", type: "bytes32" },
          { name: "ensName", type: "string" },
          { name: "resolver", type: "address" },
          { name: "recordType", type: "string" },
          { name: "recordDataHash", type: "bytes32" },
          { name: "issuer", type: "address" },
          { name: "expires", type: "uint64" },
          { name: "nonce", type: "uint256" },
        ],
      },
      { name: "userSignature", type: "bytes" },
    ],
    outputs: [{ name: "contentKey", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revokeRecord",
    inputs: [
      { name: "node", type: "bytes32" },
      { name: "recordType", type: "string" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "computeContentKey",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "node", type: "bytes32" },
          { name: "ensName", type: "string" },
          { name: "resolver", type: "address" },
          { name: "recordType", type: "string" },
          { name: "recordDataHash", type: "bytes32" },
          { name: "issuer", type: "address" },
          { name: "expires", type: "uint64" },
          { name: "nonce", type: "uint256" },
        ],
      },
      { name: "userSignature", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bytes32" }],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "verifyContentKey",
    inputs: [
      { name: "contentKey", type: "bytes32" },
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "node", type: "bytes32" },
          { name: "ensName", type: "string" },
          { name: "resolver", type: "address" },
          { name: "recordType", type: "string" },
          { name: "recordDataHash", type: "bytes32" },
          { name: "issuer", type: "address" },
          { name: "expires", type: "uint64" },
          { name: "nonce", type: "uint256" },
        ],
      },
      { name: "userSignature", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "nonces",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "RECORD_REQUEST_TYPEHASH",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "VerifiableRecordSet",
    inputs: [
      { name: "node", type: "bytes32", indexed: true },
      { name: "issuer", type: "address", indexed: true },
      { name: "contentKey", type: "bytes32", indexed: true },
      { name: "recordType", type: "string", indexed: false },
    ],
  },
  {
    type: "event",
    name: "VerifiableRecordRevoked",
    inputs: [
      { name: "node", type: "bytes32", indexed: true },
      { name: "issuer", type: "address", indexed: true },
      { name: "recordType", type: "string", indexed: false },
    ],
  },
] as const;

// ─── IssuerRegistry ABI ─────────────────────────────────────────────────────

export const IssuerRegistryABI = [
  {
    type: "function",
    name: "getIssuer",
    inputs: [{ name: "issuer", type: "address" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "name", type: "string" },
          { name: "supportedRecordTypes", type: "uint256" },
          { name: "verificationMode", type: "uint8" },
          { name: "registeredAt", type: "uint64" },
          { name: "expires", type: "uint64" },
          { name: "active", type: "bool" },
          { name: "verifierContract", type: "address" },
          { name: "specificationURI", type: "string" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "isActiveIssuer",
    inputs: [{ name: "issuer", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getIssuerVerificationMode",
    inputs: [{ name: "issuer", type: "address" }],
    outputs: [{ name: "", type: "uint8" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "registerIssuer",
    inputs: [
      { name: "issuer", type: "address" },
      { name: "name", type: "string" },
      { name: "supportedRecordTypes", type: "uint256" },
      { name: "mode", type: "uint8" },
      { name: "expires", type: "uint64" },
      { name: "verifierContract", type: "address" },
      { name: "specificationURI", type: "string" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revokeIssuer",
    inputs: [
      { name: "issuer", type: "address" },
      { name: "reason", type: "string" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "pauseIssuer",
    inputs: [{ name: "issuer", type: "address" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "unpauseIssuer",
    inputs: [{ name: "issuer", type: "address" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "renewIssuer",
    inputs: [
      { name: "issuer", type: "address" },
      { name: "newExpiry", type: "uint64" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "event",
    name: "IssuerRegistered",
    inputs: [
      { name: "issuer", type: "address", indexed: true },
      { name: "name", type: "string", indexed: false },
      { name: "supportedRecordTypes", type: "uint256", indexed: false },
      { name: "verificationMode", type: "uint8", indexed: false },
      { name: "expires", type: "uint64", indexed: false },
    ],
  },
  {
    type: "event",
    name: "IssuerRevoked",
    inputs: [
      { name: "issuer", type: "address", indexed: true },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    type: "event",
    name: "IssuerStatusChanged",
    inputs: [
      { name: "issuer", type: "address", indexed: true },
      { name: "active", type: "bool", indexed: false },
    ],
  },
] as const;

// ─── ENS Registry ABI ────────────────────────────────────────────────────────

export const ENSRegistryABI = [
  {
    type: "function",
    name: "owner",
    inputs: [{ name: "node", type: "bytes32" }],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
] as const;

// ─── TextResolver ABI ───────────────────────────────────────────────────────

export const TextResolverABI = [
  {
    type: "function",
    name: "text",
    inputs: [
      { name: "node", type: "bytes32" },
      { name: "key", type: "string" },
    ],
    outputs: [{ name: "", type: "string" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "setText",
    inputs: [
      { name: "node", type: "bytes32" },
      { name: "key", type: "string" },
      { name: "value", type: "string" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;
