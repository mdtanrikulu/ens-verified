pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/// Proves a person's age is >= 18 without revealing their birthday.
///
/// Private input:  birthday (unix timestamp)
/// Public input:   currentDate (unix timestamp — verifier checks freshness)
/// Public outputs: birthdayHash (Poseidon commitment), isAdult (1 if age >= 18)
///
/// The birthday commitment (birthdayHash) becomes the recordDataHash on-chain,
/// binding the ZK proof to the ENS verifiable record.
template AgeVerification() {
    signal input birthday;        // private: unix timestamp of birth
    signal input currentDate;     // public: current unix timestamp

    signal output birthdayHash;   // Poseidon(birthday) — non-reversible commitment
    signal output isAdult;        // 1 if age >= 18 years, 0 otherwise

    // 18 years in seconds (365.25 days/year accounts for leap years)
    // 18 * 365.25 * 86400 = 568,036,800
    var EIGHTEEN_YEARS = 568036800;

    // Age in seconds — if birthday > currentDate, this wraps to a huge field
    // element that won't fit in 40 bits, making proof generation fail.
    signal ageSeconds;
    ageSeconds <== currentDate - birthday;

    // Check: ageSeconds >= 18 years
    // 40 bits covers timestamps up to year ~36812
    component ageCheck = GreaterEqThan(40);
    ageCheck.in[0] <== ageSeconds;
    ageCheck.in[1] <== EIGHTEEN_YEARS;
    isAdult <== ageCheck.out;

    // Commit to the birthday so the claim can't be changed after issuance
    component hasher = Poseidon(1);
    hasher.inputs[0] <== birthday;
    birthdayHash <== hasher.out;
}

component main {public [currentDate]} = AgeVerification();
