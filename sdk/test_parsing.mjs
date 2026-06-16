import { parseRecordValue, buildRecordKey } from './src/utils.js';

// Test parsing per spec Section 3
// Value format: "{contentKey} {expires}" separated by single space

const testValue = "0xa23f163464ea35a52ab293ffcb1a2eee9fd79fba48a46fa58ec59adcf20c57b6 1735689600";
const result = parseRecordValue(testValue);

console.log("Parsed contentKey:", result.contentKey);
console.log("Parsed expires:   ", result.expires.toString());
console.log("Expected expires: 1735689600");
console.log("Match:", result.expires === 1735689600n);

// Test record key format per spec Section 2
// Format: vr:{lowercase-issuer}:{recordType}
const issuer = "0x2222222222222222222222222222222222222222";
const recordType = "identity";
const key = buildRecordKey(issuer, recordType);

console.log("\nRecord key:", key);
console.log("Expected format: vr:0x2222...:(recordType)");
console.log("Is lowercase:", key === key.toLowerCase());
