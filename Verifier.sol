// SPDX-License-Identifier: MIT
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x26a107379b2c1fd42a4cbbddebd15cf0bf63c45ba02be0f1bb16d90e8f91a134), uint256(0x2a5ff151d9db2465b30da34096255d0cce2afa119e74ce63ffcb50d4b6639fc8));
        vk.beta = Pairing.G2Point([uint256(0x049e4d9948d77d64080360b9450906602e14209f4085a6c24b2663a60c11e3ca), uint256(0x180f28e18a4ef84ba8459d2736aec303e434b43f13f1dbbd42181e0bfc1a19ef)], [uint256(0x2092c9f9fdb9225d3eb9a1587c245e179323df302423d896aace9e536d0eb95b), uint256(0x2b1ec3c7df6004bd790d56a806e0d165489e0f50a6030015ac3919d569e72f8f)]);
        vk.gamma = Pairing.G2Point([uint256(0x14c096f8791328d0fafbf882a750fcefe9ce619bfae5580576a15a7309e70583), uint256(0x2e42d0cd9485eb464635e9a8ab5a91a146f7a5135d28fc716e2051ed9a6dd698)], [uint256(0x0180c4590b722ad96a5a126c9a846b7e1b6cd1e16b8cee763977d7dcccfe14b8), uint256(0x0161fe9fae3ac5749948119d055a62bbcae0a463597e1aa97dc765918afe5ebf)]);
        vk.delta = Pairing.G2Point([uint256(0x113ad55bf93bca911f05f4bf8e5524a7b6531bf825f93d98bf101c30e2ce1e92), uint256(0x2bff5dd10683a904d0efdbb4b42e7465c74a3c5e7d6a485891487bf0d0b7c47f)], [uint256(0x22eeaf8ebc80300a38784cfa09a1e5672427b594597d9f04b559de0910d91e52), uint256(0x109b8e59222f6b0bc61fdad17725fe2fa1592e509165526ccb60e32174ed2854)]);
        vk.gamma_abc = new Pairing.G1Point[](2);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x24a75b7c031c066972fec38bc005e9e1f033eae204faa1f2184078f5abc5b9c7), uint256(0x1e9464ac0a59487e0c13edfde260975d499f1245dca87481b81f51ca2a0743d7));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x213536f66af0081285932e2fe55a06c507a6877124f93889f8ed60040de3fd94), uint256(0x03ecfe703ff2dfdd1527a569518332840d031fc7bd07be1708e600b7460d1cf4));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[1] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](1);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}

//  PROOF : [["0x1453389145cd1e3895c422a5692feb3d58a66607a89c7efe9a2ea6201f3c4d42","0x13ae3d4243b86b97803ed35775f359deaf9dc2a507d6e637f6dca38f5e9528d0"],[["0x19a496eb2fa4db4aac673a0fb1208b559377654b2ab55f1053082ae1be259809","0x065f6e14c7064dc06ed9ac806c5bd0c63ba0429d0d70b583c604c162e6b345e5"],["0x1c59f9b05cd1176d268879f040368f72b86f6a0fbfcf0ab221fcb76b9341618e","0x1d243ef562c132ed9619e50141f427350a6baf31ab6790bd7b06e514fa1cc492"]],["0x0e4e47f177e77f77a1baa5b10f7ceab435da6b95e1c98f7c0aceb8894e53799e","0x0233cca141cfd4a5d4119a79e49cb9dc55306ac60f26a033b039f1666c96c6e8"]],["0x0000000000000000000000000000000000000000000000000000000000000001"]