pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";

/// Proves knowledge of a secret whose Poseidon hash equals a public commitment.
/// Used as a minimal ZK proof verifier example for ENS Verifiable Records.
template CommitmentProof() {
    signal input secret;       // private — the knowledge being proven
    signal output commitment;  // public — verified on-chain as recordDataHash

    component hasher = Poseidon(1);
    hasher.inputs[0] <== secret;
    commitment <== hasher.out;
}

component main = CommitmentProof();
