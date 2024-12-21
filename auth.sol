// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Verifier.sol"; // Import the zk-SNARK verifier contract

contract AuthorizationManager {
    Verifier verifier;

    event AuthorizationRequested(
        bytes32 indexed requestHash,
        address indexed requester,
        address indexed prover,
        string reason
    );
    event ProofSubmitted(
        bytes32 indexed requestHash,
        address prover,
        bool success
    );

    struct Request {
        address requester;         // Who is asking for authorization
        address prover;            // Who needs to prove their identity
        string reasonForVerification; // Reason for the authorization request
        bytes32 proofHash;         // Hash of the proof for verification
        bool authorized;           // Whether the request has been authorized
    }

    mapping(bytes32 => Request) private requests; // Mapping of RequestHash to Request details
    bytes32[] private allRequestHashes;           // List of all RequestHashes

    constructor(address verifierAddress) {
        verifier = Verifier(verifierAddress);
    }

    /// A user requests another user for authorization
    function requestAuthorization(
        address prover,
        string memory reason,
        bytes32 proofHash
    ) public returns (bytes32 requestHash) {
        requestHash = keccak256(abi.encodePacked(
            msg.sender,
            prover,
            reason,
            proofHash,
            block.timestamp
        ));

        require(requests[requestHash].requester == address(0), "Request already exists");

        // Create a new authorization request
        requests[requestHash] = Request({
            requester: msg.sender,
            prover: prover,
            reasonForVerification: reason,
            proofHash: proofHash,
            authorized: false
        });

        // Add to the list of all request hashes
        allRequestHashes.push(requestHash);

        emit AuthorizationRequested(requestHash, msg.sender, prover, reason);
    }

    /// The prover submits proof for a specific authorization request
    function proveAuthorization(
        bytes32 requestHash,
        Verifier.Proof memory proof,
        uint[1] memory input
    ) public {
        Request storage request = requests[requestHash];

        require(request.prover != address(0), "Request not found");
        require(request.prover == msg.sender, "You are not the prover for this request");
        require(!request.authorized, "Request already authorized");

        // Verify the zk-SNARK proof
        bool proofValid = verifier.verifyTx(proof, input);
        require(proofValid, "Invalid zk-SNARK proof");

        // Mark the request as authorized
        request.authorized = true;

        emit ProofSubmitted(requestHash, msg.sender, true);
    }

    /// Retrieve details of an authorization request using its hash
    function getRequestDetails(bytes32 requestHash) public view returns (
        address requester,
        address prover,
        string memory reason,
        bytes32 proofHash,
        bool authorized
    ) {
        Request memory request = requests[requestHash];
        require(request.requester != address(0), "Request not found");

        return (
            request.requester,
            request.prover,
            request.reasonForVerification,
            request.proofHash,
            request.authorized
        );
    }

    /// Fetch all request hashes
    function getAllRequestHashes() public view returns (bytes32[] memory) {
        return allRequestHashes;
    }

    /// Get the total number of requests
    function getTotalRequests() public view returns (uint) {
        return allRequestHashes.length;
    }
}


//0x0e35310837ce6ac6617a16db0cf7598a