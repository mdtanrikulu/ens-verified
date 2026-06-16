import { keccak256, toHex, toBytes, encodePacked } from 'viem';

// Test vector from ENSIP.md Section 4
const userSignature = "0xdead01";  
const ensName = "alice.eth";
const resolver = "0x1111111111111111111111111111111111111111";
const recordDataHash = "0x00000000000000000000000000000000000000000000000000000000deadbeef";
const issuer = "0x2222222222222222222222222222222222222222";

const nameHash = keccak256(toHex(toBytes(ensName)));
console.log("keccak256('alice.eth') =", nameHash);
console.log("Expected:              0x08fa227fd019b562e0db08881c53ee5d3c7f10bff4becb46914a9481c62c3034");
console.log("Match:", nameHash === "0x08fa227fd019b562e0db08881c53ee5d3c7f10bff4becb46914a9481c62c3034");

const packed = encodePacked(
  ["bytes", "bytes32", "address", "bytes32", "address"],
  [userSignature, nameHash, resolver, recordDataHash, issuer]
);
console.log("\nEncoded length:", (packed.length - 2) / 2, "bytes (expected 107)");

const contentKey = keccak256(packed);
console.log("\nContent key:  ", contentKey);
console.log("Expected:      0xa23f163464ea35a52ab293ffcb1a2eee9fd79fba48a46fa58ec59adcf20c57b6");
console.log("Match:", contentKey === "0xa23f163464ea35a52ab293ffcb1a2eee9fd79fba48a46fa58ec59adcf20c57b6");
