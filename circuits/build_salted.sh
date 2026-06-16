#!/usr/bin/env bash
# Regenerate the SALTED age-verification circuit artifacts + Solidity verifier.
#
# Prerequisite: `circom` compiler on PATH (https://docs.circom.io/getting-started/installation/).
# snarkjs is already a devDependency. A Powers-of-Tau file (pot12_final.ptau) is reused from
# the existing build/ directory.
#
# IMPORTANT: the Phase-2 contribution below is a SINGLE local "demo" contribution — the same
# demo-grade trust level as the current artifacts. For any non-demo use, run a real multi-party
# Phase-2 ceremony finalized with a public verifiable random beacon and publish the transcript
# before shipping the regenerated Groth16 verifier.
set -euo pipefail
cd "$(dirname "$0")"

CIRCUIT=age_verification_salted
OUT=build
PTAU=$OUT/pot12_final.ptau

command -v circom >/dev/null || { echo "ERROR: circom not found on PATH"; exit 1; }
[ -f "$PTAU" ] || { echo "ERROR: $PTAU missing (Powers of Tau)"; exit 1; }

echo "==> compiling $CIRCUIT.circom"
# circom's .wat->.wasm write produces corrupt (null-filled) output on some bind-mounted
# filesystems (e.g. virtiofs). Compile in a temp dir on a normal fs, then copy artifacts back.
TMPC="$(mktemp -d "${TMPDIR:-/tmp}/circom_${CIRCUIT}.XXXXXX")"
trap 'rm -rf "$TMPC"' EXIT
cp "$CIRCUIT.circom" "$TMPC/"
ln -s "$(pwd)/node_modules" "$TMPC/node_modules"
( cd "$TMPC" && circom "$CIRCUIT.circom" --r1cs --wasm --sym -o . -l node_modules )
rm -rf "$OUT/${CIRCUIT}_js"
mkdir -p "$OUT/${CIRCUIT}_js"
cp -f "$TMPC/${CIRCUIT}_js"/* "$OUT/${CIRCUIT}_js/"
cp -f "$TMPC/$CIRCUIT.r1cs" "$TMPC/$CIRCUIT.sym" "$OUT/"

echo "==> groth16 setup"
npx snarkjs groth16 setup "$OUT/$CIRCUIT.r1cs" "$PTAU" "$OUT/${CIRCUIT}_0000.zkey"

echo "==> phase-2 contribution (DEMO ONLY)"
ENTROPY="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')"
npx snarkjs zkey contribute "$OUT/${CIRCUIT}_0000.zkey" "$OUT/${CIRCUIT}_final.zkey" \
  --name="salted demo contribution" -e="$ENTROPY"

echo "==> export verification key"
npx snarkjs zkey export verificationkey "$OUT/${CIRCUIT}_final.zkey" "$OUT/${CIRCUIT}_vkey.json"

echo "==> export Solidity verifier -> $OUT/Groth16VerifierSalted.sol"
npx snarkjs zkey export solidityverifier "$OUT/${CIRCUIT}_final.zkey" "$OUT/Groth16VerifierSalted.sol"

cat <<'NEXT'

Done. To wire the salted circuit into the demo:
  1. Replace src/verifiers/Groth16Verifier.sol with build/Groth16VerifierSalted.sol
     (rename the contract to Groth16Verifier; the 3 public signals are unchanged, so
     ZkAgeVerifier.sol needs no change).
  2. Copy build/age_verification_salted_js/age_verification_salted.wasm and
     build/age_verification_salted_final.zkey + _vkey.json into demo/public/.
  3. Update demo/src/setup.ts to generate a CSPRNG `salt`, pass {birthday, salt, currentDate}
     to the witness, persist the salt with the user record, and use Poseidon(birthday, salt)
     as recordDataHash.
NEXT
