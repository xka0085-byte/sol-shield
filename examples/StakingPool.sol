// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title StakingPool - A realistic staking contract with rewards
/// @notice Tests: access control, pausable, vault accounting, reentrancy patterns
contract StakingPool {
    address public owner;
    bool public paused;

    mapping(address => uint256) public stakes;
    mapping(address => uint256) public rewardDebt;
    uint256 public totalStaked;
    uint256 public rewardPerToken;
    uint256 public lastUpdateTime;
    uint256 public rewardRate;

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 reward);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    constructor(uint256 _rewardRate) {
        owner = msg.sender;
        rewardRate = _rewardRate;
        lastUpdateTime = block.timestamp;
    }

    function stake() external payable whenNotPaused {
        require(msg.value > 0, "Cannot stake 0");
        _updateReward(msg.sender);
        stakes[msg.sender] += msg.value;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    /// @notice Intentional reentrancy vulnerability for testing
    function unstake(uint256 amount) external whenNotPaused {
        require(stakes[msg.sender] >= amount, "Insufficient stake");
        _updateReward(msg.sender);

        // BUG: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        stakes[msg.sender] -= amount;
        totalStaked -= amount;
        emit Unstaked(msg.sender, amount);
    }

    function claimReward() external whenNotPaused {
        _updateReward(msg.sender);
        uint256 reward = rewardDebt[msg.sender];
        require(reward > 0, "No reward");
        rewardDebt[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: reward}("");
        require(success, "Transfer failed");
        emit RewardClaimed(msg.sender, reward);
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function setRewardRate(uint256 _rate) external onlyOwner {
        rewardRate = _rate;
    }

    function _updateReward(address account) internal {
        if (totalStaked > 0) {
            rewardPerToken += (block.timestamp - lastUpdateTime) * rewardRate / totalStaked;
        }
        lastUpdateTime = block.timestamp;
        rewardDebt[account] = stakes[account] * rewardPerToken;
    }

    receive() external payable {}
}
