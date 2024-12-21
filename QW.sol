// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureToken {
    string public name = "Qrupee";
    string public symbol = "QR";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    uint256 public maxTransactionAmount;
    uint256 public exchangeRate; 
    address public owner;

    mapping(address => uint256) public balanceOf;
    mapping(bytes32 => Transaction) public pendingTransactions;
    mapping(address => bytes32[]) public userTransactions;

    struct Transaction {
        address sender;
        address receiver;
        uint256 amount;
        bytes32 codeHash;
        bool isClaimed;
        address[] signatories;
        mapping(address => bool) approvals;
        uint256 approvalCount;
    }

    event TransferInitiated(
        address indexed sender,
        address indexed receiver,
        uint256 amount,
        bytes32 transactionId
    );

    event TransferClaimed(
        address indexed receiver,
        bytes32 transactionId,
        uint256 amount
    );

    event TransactionSigned(
        address indexed signer,
        bytes32 transactionId
    );

    event EtherSwapped(
        address indexed user,
        uint256 etherAmount,
        uint256 qrupeeAmount
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    constructor(uint256 _initialSupply, uint256 _maxTransactionAmount, uint256 _exchangeRate) {
        totalSupply = _initialSupply * (10 ** uint256(decimals));
        balanceOf[msg.sender] = totalSupply;
        maxTransactionAmount = _maxTransactionAmount;
        exchangeRate = _exchangeRate;
        owner = msg.sender;
    }

    function setTransactionLimit(uint256 _maxTransactionAmount) public onlyOwner {
        maxTransactionAmount = _maxTransactionAmount;
    }

    function setExchangeRate(uint256 _exchangeRate) public onlyOwner {
        require(_exchangeRate > 0, "Exchange rate must be greater than 0");
        exchangeRate = _exchangeRate;
    }

    function swapEtherForQrupee() public payable {
        require(msg.value > 0, "Must send Ether to swap");
        uint256 qrupeeAmount = msg.value * exchangeRate;

        require(
            balanceOf[owner] >= qrupeeAmount,
            "Not enough Qrupees available in the contract"
        );

        balanceOf[owner] -= qrupeeAmount;
        balanceOf[msg.sender] += qrupeeAmount;

        emit EtherSwapped(msg.sender, msg.value, qrupeeAmount);
    }

    function withdrawEther() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function initiateTransfer(
        address _receiver,
        uint256 _amount,
        string memory _code,
        address[] memory _signatories
    ) public returns (bytes32 transactionId) {
        require(_amount > 0, "Amount must be greater than 0");
        require(
            _amount <= maxTransactionAmount,
            "Transaction amount exceeds the limit"
        );
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");
        require(_receiver != address(0), "Invalid receiver address");

        bytes32 codeHash = keccak256(abi.encodePacked(_code));
        transactionId = keccak256(
            abi.encodePacked(msg.sender, _receiver, block.timestamp, _amount)
        );

        Transaction storage txn = pendingTransactions[transactionId];
        txn.sender = msg.sender;
        txn.receiver = _receiver;
        txn.amount = _amount;
        txn.codeHash = codeHash;
        txn.isClaimed = false;
        txn.signatories = _signatories;

        balanceOf[msg.sender] -= _amount;
        userTransactions[_receiver].push(transactionId);

        emit TransferInitiated(msg.sender, _receiver, _amount, transactionId);
        return transactionId;
    }

    function signTransaction(bytes32 _transactionId) public {
        Transaction storage txn = pendingTransactions[_transactionId];
        require(txn.receiver != address(0), "Transaction does not exist");
        require(!txn.isClaimed, "Transaction already claimed");
        require(
            isSignatory(_transactionId, msg.sender),
            "Caller is not an authorized signatory"
        );
        require(
            !txn.approvals[msg.sender],
            "Transaction already signed by caller"
        );

        txn.approvals[msg.sender] = true;
        txn.approvalCount++;

        emit TransactionSigned(msg.sender, _transactionId);
    }

    function claimTransfer(bytes32 _transactionId, string memory _code) public {
        Transaction storage txn = pendingTransactions[_transactionId];
        require(txn.receiver == msg.sender, "Not authorized to claim");
        require(!txn.isClaimed, "Transaction already claimed");
        require(
            txn.codeHash == keccak256(abi.encodePacked(_code)),
            "Invalid code"
        );
        require(
            txn.approvalCount >= (txn.signatories.length + 1) / 2,
            "Insufficient signatory approvals"
        );

        txn.isClaimed = true;
        balanceOf[msg.sender] += txn.amount;

        emit TransferClaimed(msg.sender, _transactionId, txn.amount);
    }

    function isSignatory(bytes32 _transactionId, address _user)
        internal
        view
        returns (bool)
    {
        Transaction storage txn = pendingTransactions[_transactionId];
        for (uint256 i = 0; i < txn.signatories.length; i++) {
            if (txn.signatories[i] == _user) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Allows a signatory to view all pending transactions they need to sign.
     * @return pendingTransactionIds Array of transaction IDs the caller needs to sign.
     */
    function getPendingSignatures() public view returns (bytes32[] memory) {
        uint256 count = 0;
        bytes32[] memory allTransactions = userTransactions[msg.sender];

        // Count the pending transactions for the caller
        for (uint256 i = 0; i < allTransactions.length; i++) {
            Transaction storage txn = pendingTransactions[allTransactions[i]];
            if (
                !txn.isClaimed &&
                isSignatory(allTransactions[i], msg.sender) &&
                !txn.approvals[msg.sender]
            ) {
                count++;
            }
        }

        // Populate the result array
        bytes32[] memory pendingTransactionIds = new bytes32[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < allTransactions.length; i++) {
            Transaction storage txn = pendingTransactions[allTransactions[i]];
            if (
                !txn.isClaimed &&
                isSignatory(allTransactions[i], msg.sender) &&
                !txn.approvals[msg.sender]
            ) {
                pendingTransactionIds[index] = allTransactions[i];
                index++;
            }
        }

        return pendingTransactionIds;
    }

    function viewSignatoryTransaction(bytes32 _transactionId)
        public
        view
        returns (
            address sender,
            address receiver,
            uint256 amount,
            bool isClaimed
        )
    {
        Transaction storage txn = pendingTransactions[_transactionId];
        require(
            isSignatory(_transactionId, msg.sender),
            "Caller is not an authorized signatory"
        );

        return (txn.sender, txn.receiver, txn.amount, txn.isClaimed);
    }

    function getClaimableTransactions() public view returns (bytes32[] memory) {
        bytes32[] memory allUserTransactions = userTransactions[msg.sender];
        uint256 count = 0;

        for (uint256 i = 0; i < allUserTransactions.length; i++) {
            if (!pendingTransactions[allUserTransactions[i]].isClaimed) {
                count++;
            }
        }

        bytes32[] memory claimableTransactions = new bytes32[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < allUserTransactions.length; i++) {
            if (!pendingTransactions[allUserTransactions[i]].isClaimed) {
                claimableTransactions[index] = allUserTransactions[i];
                index++;
            }
        }

        return claimableTransactions;
    }
}
// 0x0e35310837ce6ac6617a16db0cf7598a