pragma circom 2.0.2;

include "../secp256k1/eth_addr.circom";
include "../merkle/merkleTree.circom";
include "../../node_modules/circomlib/circuits/pedersen.circom";

template Main(levels, n, k) {
    signal input root;
    signal input privkey[k];
    signal input tokenId;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component privToAddr = PrivKeyToAddr(n, k);
    for (var i = 0; i < k; i++) {
        privToAddr.privkey[i] <== privkey[i];
    }
    
    component commitmentHasher = Pedersen(496);
    component nullifierBits = Num2Bits(248);
    component secretBits = Num2Bits(248);
    nullifierBits.in <== privToAddr.addr;
    secretBits.in <== tokenId;
    for (var i = 0; i < 248; i++) {
        commitmentHasher.in[i] <== nullifierBits.out[i];
        commitmentHasher.in[i + 248] <== secretBits.out[i];
    }

    component tree = MerkleTreeChecker(levels);
    tree.leaf <== commitmentHasher.out[0];
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
}

component main {public [root]} = Main(1, 86, 3);
