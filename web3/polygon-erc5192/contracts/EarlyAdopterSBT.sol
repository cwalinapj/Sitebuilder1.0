// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC5192 {
  event Locked(uint256 tokenId);
  event Unlocked(uint256 tokenId);
  function locked(uint256 tokenId) external view returns (bool);
}

/// @notice ERC-5192 soulbound token for early adopters. Non-transferable by design.
contract EarlyAdopterSBT is ERC721, Ownable, IERC5192 {
  uint256 private _nextId = 1;
  string private _baseTokenURI;

  constructor(string memory name_, string memory symbol_, string memory baseURI_) ERC721(name_, symbol_) Ownable(msg.sender) {
    _baseTokenURI = baseURI_;
  }

  function locked(uint256 tokenId) external view override returns (bool) {
    return _exists(tokenId);
  }

  function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
    return interfaceId == type(IERC5192).interfaceId || super.supportsInterface(interfaceId);
  }

  function setBaseURI(string memory baseURI_) external onlyOwner {
    _baseTokenURI = baseURI_;
  }

  function mint(address to) external onlyOwner returns (uint256 tokenId) {
    tokenId = _nextId++;
    _safeMint(to, tokenId);
    emit Locked(tokenId);
  }

  function _baseURI() internal view override returns (string memory) {
    return _baseTokenURI;
  }

  function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize) internal override {
    super._beforeTokenTransfer(from, to, tokenId, batchSize);
    if (from != address(0) && to != address(0)) {
      revert("SBT: non-transferable");
    }
  }

  function approve(address, uint256) public pure override {
    revert("SBT: approvals disabled");
  }

  function setApprovalForAll(address, bool) public pure override {
    revert("SBT: approvals disabled");
  }
}
