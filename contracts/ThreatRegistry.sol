// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ThreatRegistry {
    struct ThreatRecord {
        bytes32 domainHash;
        uint8 severityScore;
        string ipfsCid;
        address reporter;
        uint256 timestamp;
    }

    mapping(bytes32 => ThreatRecord) public registry;

    event ThreatLogged(
        bytes32 indexed domainHash,
        uint8 severityScore,
        string ipfsCid,
        address indexed reporter,
        uint256 timestamp
    );

    function reportThreat(
        string memory domain,
        uint8 severityScore,
        string memory ipfsCid
    ) external {
        bytes32 domainHash = keccak256(abi.encodePacked(domain));
        
        registry[domainHash] = ThreatRecord({
            domainHash: domainHash,
            severityScore: severityScore,
            ipfsCid: ipfsCid,
            reporter: msg.sender,
            timestamp: block.timestamp
        });

        emit ThreatLogged(domainHash, severityScore, ipfsCid, msg.sender, block.timestamp);
    }

    function verifyDomain(string memory domain) external view returns (
        bool exists,
        uint8 score,
        string memory ipfsCid,
        address reporter,
        uint256 timestamp
    ) {
        bytes32 domainHash = keccak256(abi.encodePacked(domain));
        ThreatRecord memory rec = registry[domainHash];
        if (rec.timestamp == 0) {
            return (false, 0, "", address(0), 0);
        }
        return (true, rec.severityScore, rec.ipfsCid, rec.reporter, rec.timestamp);
    }
}