// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Groth16Verifier} from "../src/verifiers/Groth16Verifier.sol";
import {ZkAgeVerifier} from "../src/verifiers/ZkAgeVerifier.sol";

/// @notice On-chain regression for the SALTED age circuit. The proof vector below was
///         produced by the salted circuit (birthdayHash = Poseidon(birthday, salt)) via
///         circuits/build_salted.sh, inputs: birthday=946684800 (Jan 1 2000),
///         salt=123456789012345678901234567890, currentDate=1900000000.
///         recordDataHash is the salted birthdayHash (public signal 0), which a brute force
///         over birthdays alone can no longer recover. Confirms src/verifiers/Groth16Verifier.sol
///         is consistent with the salted ceremony shipped in demo/public/.
contract ZkAgeVerifierTest is Test {
    Groth16Verifier internal groth16;
    ZkAgeVerifier internal zk;

    uint256 internal constant CURRENT_DATE = 1900000000;
    bytes32 internal constant SALTED_BIRTHDAY_HASH = 0x1d4e3097db4445289dab0fdc53a8adf869d3e7375a6ddd8412e766967801454d;

    function setUp() public {
        groth16 = new Groth16Verifier();
        zk = new ZkAgeVerifier(address(groth16));
    }

    function _proof() internal pure returns (bytes memory) {
        uint256[2] memory pA = [
            0x16ce93dd41d6f34461772edc2d0aafe406fab3d97b93470dd68f45b2ae47d5ca,
            0x29434b69015293601afc0cca64ec53535d4644b34c46a2da16338bfa1390ebe0
        ];
        uint256[2][2] memory pB;
        pB[0][0] = 0x028b474892a238cdf66218a608f15f15c9e100617f0755d4c87cec78c70d38b2;
        pB[0][1] = 0x0408d4a12cf66b13e69f7feff08956f9916b6d890c79d01ff85b983eeacdb07e;
        pB[1][0] = 0x036e97f6f25bd7655b52338f98520cc05effa1f484cdc590f877d0b6847a2549;
        pB[1][1] = 0x108ba9ac3bdc7b4d0ced363d430e5af5560fdde5a4c600d7790b3e45cd7e1866;
        uint256[2] memory pC = [
            0x070eee10d3d207ead3a7383c6343c29efeba0f07393dfa3f4a0ebbf85e956d92,
            0x1c5fda788d1eaba5b75fbde044799c51f18e6c708d894d3d272ec66f148c1768
        ];
        return abi.encode(pA, pB, pC, CURRENT_DATE);
    }

    function test_saltedProof_verifiesOnChain() public {
        vm.warp(CURRENT_DATE);
        assertTrue(zk.verifyProof(_proof(), SALTED_BIRTHDAY_HASH, address(0xBEEF)));
    }

    function test_saltedProof_wrongRecordDataHash_fails() public {
        vm.warp(CURRENT_DATE);
        // Any other recordDataHash (e.g. an unsalted Poseidon(birthday) guess) must not verify.
        assertFalse(zk.verifyProof(_proof(), bytes32(uint256(1)), address(0xBEEF)));
    }

    function test_saltedProof_futureDate_rejected() public {
        vm.warp(1000); // now << currentDate - drift
        assertFalse(zk.verifyProof(_proof(), SALTED_BIRTHDAY_HASH, address(0xBEEF)));
    }
}
