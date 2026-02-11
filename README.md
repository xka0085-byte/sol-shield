# sol-shield

Static analysis tool that auto-discovers invariant properties, detects vulnerabilities, and generates [Foundry](https://book.getfoundry.sh/) fuzz/invariant tests for Solidity smart contracts.

> "Fuzz and invariant tests are the new bare minimum." — Patrick Collins, Cyfrin

## Why

Writing invariant tests is tedious. Most teams skip them. sol-shield reads your contract's AST and generates ready-to-run Foundry test suites — complete with Handler contracts, ghost variables, and actor management.

## Install

```bash
npm install -g sol-shield
```

## Quick Start

```bash
# Full analysis + test generation
sol-shield full MyContract.sol

# Analysis only (no file output)
sol-shield analyze MyContract.sol

# Generate tests only
sol-shield generate MyContract.sol -o ./test
```

## What It Does

### 1. Invariant Discovery
Automatically identifies properties that must always hold:

| Pattern | Example |
|---------|---------|
| ERC20 supply | `totalSupply == sum(balanceOf)` |
| Vault accounting | `totalDeposited == sum(balances)` |
| Solvency | `address(contract).balance >= totalDeposited` |
| Access control | `owner` only changes through authorized functions |
| Pausable | Protected functions revert when paused |
| Arithmetic | Subtraction operations can't underflow |

### 2. Test Generation
Generates complete Foundry test files:
- **Handler contracts** with bounded inputs and actor management
- **Ghost variables** that track cumulative state changes
- **Invariant test contracts** with `invariant_*` functions
- **Vulnerability PoC tests** with `test_*` exploit scenarios

### 3. Vulnerability Detection
Scans for common security issues:
- Reentrancy (SWC-107)
- Unchecked return values (SWC-104)
- Missing access control (SWC-105)
- Front-running risks (SWC-114)
- DoS with failed calls (SWC-113)

## Example Output

```
  sol-shield v0.1.0
  Analyzing: Vault.sol

  Contract: Vault
  ────────────────────────────────────────

  [CRITICAL] Vault Accounting Integrity
    > totalDeposited must equal sum of all balances
    Assert: assertEq(vault.totalDeposited(), handler.ghost_balanceSum())

  [CRITICAL] Reentrancy in withdraw()
    > External call at line 38 occurs BEFORE state updates at line(s) 41, 42
    Fix: Use Checks-Effects-Interactions pattern or reentrancy guard

  Generated test files:
    > test/Vault.invariant.t.sol
    > test/Vault.vuln.t.sol
```

## Generated Test Structure

```
test/
├── Vault.invariant.t.sol    # Handler + invariant tests
└── Vault.vuln.t.sol         # Vulnerability PoC tests
```

The invariant test file includes:
- A **Handler** contract that wraps all state-changing functions with bounded inputs
- Ghost variables for tracking cumulative state (e.g., `ghost_balanceSum`)
- Multi-actor support via `prank()` for realistic call sequences
- Invariant functions that Foundry's fuzzer will try to break

## Supported Patterns

- ERC20 tokens (supply, transfer, allowance)
- ERC721 NFTs (ownership, uniqueness)
- Vault/Staking contracts (accounting, solvency)
- Access-controlled contracts (owner, admin)
- Pausable contracts
- Any contract with mappings + totals

## Limitations

- Single-file analysis only (no cross-file imports yet)
- Generated tests may need minor edits for complex constructors
- Best results with standard patterns (ERC20, Vault, etc.)

## Support This Project

If sol-shield helped you catch bugs or saved you time, consider supporting development:

**ETH/Base/Arbitrum/Optimism**: `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1`

Your support helps maintain and improve this tool. Thank you! 🙏

## License

MIT
