// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract IntegrityRegistry {
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public writers;
    mapping(bytes32 => bool) public usedVersionIds;
    struct VersionRecord { bytes32 digest; uint64 timestamp; bool exists; }
    mapping(bytes32 => mapping(bytes32 => VersionRecord)) private records;
    event WriterUpdated(address indexed writer, bool enabled);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event VersionRegistered(bytes32 indexed fileId, bytes32 indexed versionId, bytes32 digest, uint64 timestamp);
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier onlyWriter() { require(writers[msg.sender], "not writer"); _; }
    constructor() { owner = msg.sender; writers[msg.sender] = true; emit WriterUpdated(msg.sender, true); }
    function setWriter(address writer, bool enabled) external onlyOwner { require(writer != address(0), "zero writer"); writers[writer] = enabled; emit WriterUpdated(writer, enabled); }
    function transferOwnership(address next) external onlyOwner { require(next != address(0), "zero owner"); pendingOwner=next; emit OwnershipTransferStarted(owner,next); }
    function acceptOwnership() external { require(msg.sender == pendingOwner, "not pending owner"); address previous=owner; owner=msg.sender; pendingOwner=address(0); emit OwnershipTransferred(previous,msg.sender); }
    function registerVersion(bytes32 fileId, bytes32 versionId, bytes32 digest) external onlyWriter {
        require(fileId != bytes32(0) && versionId != bytes32(0), "zero identifier");
        require(digest != bytes32(0), "zero digest");
        require(!usedVersionIds[versionId], "version already registered");
        require(!records[fileId][versionId].exists, "version already registered");
        uint64 timestamp = uint64(block.timestamp);
        usedVersionIds[versionId] = true;
        records[fileId][versionId] = VersionRecord(digest,timestamp,true);
        emit VersionRegistered(fileId,versionId,digest,timestamp);
    }
    function getVersion(bytes32 fileId, bytes32 versionId) external view returns (bytes32 digest,uint64 timestamp,bool exists) {
        VersionRecord memory record = records[fileId][versionId];
        return (record.digest,record.timestamp,record.exists);
    }
}
