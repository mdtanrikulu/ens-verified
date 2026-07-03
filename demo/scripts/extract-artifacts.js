// Regenerates demo/src/artifacts.ts from forge's out/ directory.
// Run from the demo/ directory after `forge build`:
//   node scripts/extract-artifacts.js

import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");
const outDir = resolve(repoRoot, "out");
const targetFile = resolve(__dirname, "..", "src", "artifacts.ts");

// Names match what demo/src/setup.ts imports from "./artifacts".
// Each entry is [exportName, forgeOutputPath].
const contracts = [
  ["IssuerRegistry", "IssuerRegistry.sol/IssuerRegistry.json"],
  ["VerifiableRecordController", "VerifiableRecordController.sol/VerifiableRecordController.json"],
  ["MockResolver", "MockResolver.sol/MockResolver.json"],
  ["ECDSAProofVerifier", "ECDSAProofVerifier.sol/ECDSAProofVerifier.json"],
  ["Groth16Verifier", "Groth16Verifier.sol/Groth16Verifier.json"],
  ["ZkAgeVerifier", "ZkAgeVerifier.sol/ZkAgeVerifier.json"],
  ["MockENSRegistry", "MockENSRegistry.sol/MockENSRegistry.json"],
];

const header = `// Auto-generated — extracted from forge build artifacts
// Run: node scripts/extract-artifacts.js
import type { Hex } from "viem";

interface Artifact { abi: readonly any[]; bytecode: Hex }

`;

const chunks = [header];

for (const [name, relPath] of contracts) {
  const artifactPath = resolve(outDir, relPath);
  const raw = JSON.parse(readFileSync(artifactPath, "utf8"));
  const abi = raw.abi ?? [];
  const bytecode = raw.bytecode?.object ?? raw.bytecode ?? "0x";
  if (!bytecode || bytecode === "0x") {
    throw new Error(`No bytecode for ${name} at ${artifactPath}`);
  }
  chunks.push(
    `export const ${name}: Artifact = {\n` +
      `  abi: ${JSON.stringify(abi)},\n` +
      `  bytecode: "${bytecode}" as Hex,\n` +
      `};\n\n`
  );
}

writeFileSync(targetFile, chunks.join(""));
console.log(`Wrote ${targetFile}`);
