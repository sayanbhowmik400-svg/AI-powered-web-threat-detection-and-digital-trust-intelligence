// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PhishLens ThreatRegistry
 * @notice Immutable decentralized log for anchoring AI-evaluated domain threat telemetry.
 */
contract ThreatRegistry {
    struct ThreatRecord {
        string domain;
        uint8 threatScore;
        string verdict;
        bytes32 telemetryHash;
        uint256 timestamp;
        address reporter;
    }

    ThreatRecord[] public records;
    mapping(string => ThreatRecord) public latestDomainRecord;

    event ThreatAnchored(
        string indexed domain,
        uint8 threatScore,
        string verdict,
        bytes32 telemetryHash,
        uint256 timestamp,
        address indexed reporter
    );

    function logThreat(
        string calldata _domain,
        uint8 _threatScore,
        string calldata _verdict,
        bytes32 _telemetryHash
    ) external {
        require(_threatScore <= 100, "Score must be 0-100");

        ThreatRecord memory newRecord = ThreatRecord({
            domain: _domain,
            threatScore: _threatScore,
            verdict: _verdict,
            telemetryHash: _telemetryHash,
            timestamp: block.timestamp,
            reporter: msg.sender
        });

        records.push(newRecord);
        latestDomainRecord[_domain] = newRecord;

        emit ThreatAnchored(
            _domain,
            _threatScore,
            _verdict,
            _telemetryHash,
            block.timestamp,
            msg.sender
        );
    }

    function getTotalRecords() external view returns (uint256) {
        return records.length;
    }
}