// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.6;

import "./openzeppelin/contracts/token/ERC721/ERC721.sol";
import "./verifier.sol";
import "./merkleTree.sol";

interface ERC0000 /* is ERC721, ERC165 */ {

    /// @notice Mints token to address and adds nullifier hash to the merkle tree
    /// @dev The nullifier hash is the MIMC hash of the abi encoded address and tokenId
    function _mint(address to, uint256 tokenId) external;

    /// @notice Burns token with specified Id from owner address and adds the
    /// nullifierHash to the nullifierHashes. 
    /// @dev The nullifierHashes mapping is used to flag nullifiers as `burned`.
    function _burn(uint256 tokenId_) external;

    /// @notice Transfers token with specified Id from sender to the recipient address 
    /// and adds the nullifier to the nullifierHashes.
    /// @dev The nullifierHashes mapping is used to flag nullifiers as `spent`.
    function _transfer(address from, address to, uint256 tokenId) external;

    /// @notice Verifies merkle-proofs from zk-SNARKs
    /// @dev The functions calls the Verifier implementation to verify a given proof
    /// @param proof The proof including the public input variables to verify 
    ///  ownership in the merkle tree
    /// @return Validity of the provided proof
    function _verifyProof(bytes calldata proof) external returns (bool);
}

/**
 * @dev Extension of ERC721 to support owernship proofs using merkle proofs
 *
 * The merkle tree stores hashes of addresses and tokenIds in its leafs. It can be used to generate 
 * merkle proofs that prove owernship, off-chain. Using zk-SNARKs (e.g. PrivToAddress Circuits), users
 * can provide a merkle proof of ownership without unveiling their identity.
 */
abstract contract ERC721MerkleProvable is ERC165, ERC721 {
    // Verifier Contract Implementation
    Verifier private _verifier;  

    // Merkle Tree Contract Implementation
    MerkleTreeWithHistory private _merkleTree;

    // Mapping from nullifier hashes to booleans indicating ``if spent``
    mapping(bytes32 => bool) public _nullifierHashes;

	constructor(
        string memory name_, 
        string memory symbol_, 
        Verifier verifier_,
        uint32 levels_, 
        IHasher hasher_
    ) ERC721(name_, symbol_) {   
        _verifier = verifier_;
        _merkleTree = new MerkleTreeWithHistory(levels_, hasher_);
    }

    /**
    * @dev See {ERC721-_mint}. This additionally adds a leaf with the nullifier (owner+tokenId) to merkle tree. 
    */
    function _mint(address to, uint256 tokenId) internal virtual override {    
        super._mint(to, tokenId);
        bytes32 nullifierHash = _merkleTree.hashLeftRight(_merkleTree.hasher(), bytes32(bytes20(to)), bytes32(tokenId));
        _merkleTree._insert(nullifierHash);
    }

    /**
    * @dev See {ERC721-_burn}. This additionally adds the tokenId to the burnedTokens. 
    */
    function _burn(uint256 tokenId) internal virtual override {
        super._burn(tokenId);
        require(!_nullifierHashes[bytes32(abi.encode(tokenId))], "ERC721MerkleProvable: nullifier already known");
        _nullifierHashes[bytes32(abi.encode(tokenId))] = true;
    }

    /**
    * @dev See {ERC721-_transfer}. This additionally updates the merkle tree and invalidates the senders nullifierHash
    *  The nullifierHash of the recipient is written to a leaf in the merkle tree and the 
    *  corresponding nullifierHash gets spendable (required for cases in which the receiver already had the token)
    */
    function _transfer(
        address from,
        address to, 
        uint256 tokenId
    ) internal virtual override {
        super._transfer(from, to, tokenId);
        bytes32 nullifierHash_sender = MIMCSponge(from, tokenId);
        require(!_nullifierHashes[nullifierHash_sender], "ERC721SNARKable: nullifier already known");
        bytes32 nullifierHash_receiver = MIMCSponge(to, tokenId);
        _nullifierHashes[nullifierHash_sender] = true;
        _merkleTree._insert(nullifierHash_receiver);
        _nullifierHashes[nullifierHash_receiver] = false;
    }

    /**
    * @dev Verifies a proof. Note that the {Verifier} implementation must be able to parse the byte-data.
    */
    function _verifyProof(bytes calldata proof) internal view returns (bool) {
        uint[] memory _proof = abi.decode(proof, (uint256[]));
        // Last element in proof MUST be the root
        require(_merkleTree.isKnownRoot(bytes32(_proof[_proof.length-1])), "Root not known");
        return _verifier.verifyProof(_proof);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, ERC721) returns (bool) {
        return interfaceId == type(ERC0000).interfaceId ||
        super.supportsInterface(interfaceId);
    }

    function MIMCSponge(address user, uint tokenId) internal view returns (bytes32) {
        return _merkleTree.hashLeftRight(_merkleTree.hasher(), bytes32(bytes20(user)), bytes32(tokenId));
    }
}
