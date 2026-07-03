pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/// Blinded age-verification circuit (ENSIP-PRIVACY "ZK Commitment Blinding").
///
/// Identical age logic to age_verification.circom, but the public commitment is
/// salted so the public `birthdayHash` is NOT a brute-force oracle for the birthday:
///
///   birthdayHash = Poseidon(birthday, salt)
///
/// Private inputs:  birthday (unix timestamp), salt (>=128-bit CSPRNG value from the issuer)
/// Public input:    currentDate (unix timestamp — verifier checks freshness)
/// Public outputs:  birthdayHash (salted Poseidon commitment), isAdult (1 if age >= 18)
///
/// The salt is a PRIVATE input — it joins the witness and is never revealed. Exposing it
/// as a public signal would re-open the oracle. The salt MUST be delivered to the user
/// over a confidential channel and persisted alongside the birthday so disclosure can
/// reproduce recordDataHash = Poseidon(birthday, salt).
///
/// NOTE: this circuit changes the constraint system, so it requires a fresh compilation
/// and trusted setup; the regenerated Groth16Verifier verifies the same 3 public signals
/// [birthdayHash, isAdult, currentDate], so ZkAgeVerifier.sol needs no interface change.
template AgeVerificationSalted() {
    signal input birthday;        // private: unix timestamp of birth
    signal input salt;            // private: >=128-bit blinding salt from the issuer
    signal input currentDate;     // public: current unix timestamp

    signal output birthdayHash;   // Poseidon(birthday, salt) — salted, non-brute-forceable
    signal output isAdult;        // 1 if age >= 18 years, 0 otherwise

    // 18 years in seconds (365.25 days/year accounts for leap years)
    var EIGHTEEN_YEARS = 568036800;

    // Age in seconds — if birthday > currentDate this wraps to a huge field element that
    // won't fit in 40 bits, making proof generation fail (caught by Num2Bits in GreaterEqThan).
    signal ageSeconds;
    ageSeconds <== currentDate - birthday;

    component ageCheck = GreaterEqThan(40);
    ageCheck.in[0] <== ageSeconds;
    ageCheck.in[1] <== EIGHTEEN_YEARS;
    isAdult <== ageCheck.out;

    // Salted commitment to the birthday so the public hash cannot be brute-forced.
    component hasher = Poseidon(2);
    hasher.inputs[0] <== birthday;
    hasher.inputs[1] <== salt;
    birthdayHash <== hasher.out;
}

component main {public [currentDate]} = AgeVerificationSalted();
