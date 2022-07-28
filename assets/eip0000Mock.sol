// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.6;

import "./eip0000.sol";

contract ERC721MerkleProvableMock is ERC721MerkleProvable {
    constructor(
        string memory name, 
        string memory symbol, 
        Verifier verifier,
        uint32 levels, 
        IHasher hasher
    ) ERC721MerkleProvable(name, symbol, verifier, levels, hasher) {}

    function mintToken(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function burnToken(uint256 tokenId) public {
        _burn(tokenId);
    }

    function transferToken( address from, address to, uint256 tokenId) public {
        _transfer(from, to, tokenId);
    }

    function verifyProof(bytes calldata proof) public view returns (bool) {
        return _verifyProof(proof);
    }
}
