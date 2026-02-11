// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    address public owner;
    bool public paused;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable whenNotPaused {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Intentional vulnerability: reentrancy
    function withdraw(uint256 amount) public whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        totalDeposited -= amount;

        emit Withdraw(msg.sender, amount);
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function unpause() public onlyOwner {
        paused = false;
    }
}
