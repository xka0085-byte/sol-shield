const chalk = require("chalk");

// Severity levels
const CRITICAL = "CRITICAL";
const HIGH = "HIGH";
const MEDIUM = "MEDIUM";
const LOW = "LOW";

/**
 * Analyze a parsed contract and discover invariant properties
 */
function discoverInvariants(contract) {
  const invariants = [];

  // Run all detection strategies
  detectERC20Invariants(contract, invariants);
  detectERC721Invariants(contract, invariants);
  detectSupplyInvariants(contract, invariants);
  detectBalanceInvariants(contract, invariants);
  detectAccessControlInvariants(contract, invariants);
  detectPausableInvariants(contract, invariants);
  detectArithmeticInvariants(contract, invariants);
  detectMappingConsistency(contract, invariants);

  // Deduplicate by id
  const seen = new Set();
  return invariants.filter((inv) => {
    if (seen.has(inv.id)) return false;
    seen.add(inv.id);
    return true;
  });
}

// ─── ERC20 Detection ───
function isERC20Like(contract) {
  const fnNames = contract.functions.map((f) => f.name);
  const hasTransfer = fnNames.includes("transfer");
  const hasBalanceOf = contract.stateVars.some(
    (v) => v.name === "balanceOf" || v.name === "balances" || v.name === "_balances"
  );
  const hasTotalSupply = contract.stateVars.some(
    (v) => v.name === "totalSupply" || v.name === "_totalSupply"
  );
  return hasTransfer && hasBalanceOf && hasTotalSupply;
}

function detectERC20Invariants(contract, invariants) {
  if (!isERC20Like(contract)) return;

  const balVar = contract.stateVars.find(
    (v) => v.name === "balanceOf" || v.name === "balances" || v.name === "_balances"
  );
  const supplyVar = contract.stateVars.find(
    (v) => v.name === "totalSupply" || v.name === "_totalSupply"
  );

  invariants.push({
    id: "erc20_supply_conservation",
    severity: CRITICAL,
    title: "Total Supply Conservation",
    description: `${supplyVar.name} must always equal the sum of all ${balVar.name}`,
    pattern: "ERC20 supply integrity",
    invariantCode: `assertEq(token.${supplyVar.name}(), handler.ghost_balanceSum())`,
    ghostVars: [
      {
        name: "ghost_balanceSum",
        type: "uint256",
        trackIn: ["transfer", "transferFrom", "mint", "_mint", "burn", "_burn"],
      },
    ],
  });

  invariants.push({
    id: "erc20_no_free_tokens",
    severity: CRITICAL,
    title: "No Token Creation From Thin Air",
    description: `${supplyVar.name} can only increase through authorized mint functions`,
    pattern: "ERC20 mint control",
    invariantCode: `assertLe(token.${supplyVar.name}(), handler.ghost_totalMinted())`,
    ghostVars: [
      {
        name: "ghost_totalMinted",
        type: "uint256",
        trackIn: ["mint", "_mint"],
      },
    ],
  });

  // Transfer symmetry
  invariants.push({
    id: "erc20_transfer_symmetry",
    severity: HIGH,
    title: "Transfer Symmetry",
    description: "For every transfer, sender decrease must equal receiver increase",
    pattern: "ERC20 transfer integrity",
    invariantCode: `assertEq(handler.ghost_senderDecrease(), handler.ghost_receiverIncrease())`,
    ghostVars: [
      { name: "ghost_senderDecrease", type: "uint256", trackIn: ["transfer", "transferFrom"] },
      { name: "ghost_receiverIncrease", type: "uint256", trackIn: ["transfer", "transferFrom"] },
    ],
  });

  // Allowance
  const hasApprove = contract.functions.some((f) => f.name === "approve");
  const hasTransferFrom = contract.functions.some((f) => f.name === "transferFrom");
  if (hasApprove && hasTransferFrom) {
    invariants.push({
      id: "erc20_allowance_decrease",
      severity: HIGH,
      title: "Allowance Decreases on TransferFrom",
      description: "transferFrom must decrease allowance by the transferred amount",
      pattern: "ERC20 allowance integrity",
      invariantCode: null, // complex, handled in generator
    });
  }

  // Zero address guard
  const transferFn = contract.functions.find((f) => f.name === "transfer");
  if (transferFn) {
    const hasZeroCheck = transferFn.requires.some(
      (r) => r.args.some((a) => a.includes("address(0)") || a.includes("zero"))
    );
    invariants.push({
      id: "erc20_zero_address",
      severity: hasZeroCheck ? LOW : MEDIUM,
      title: "Zero Address Guard",
      description: "transfer/transferFrom to address(0) should revert",
      pattern: "Input validation",
      invariantCode: null,
    });
  }
}

// ─── ERC721 Detection ───
function isERC721Like(contract) {
  const fnNames = contract.functions.map((f) => f.name);
  return (
    fnNames.includes("ownerOf") ||
    (fnNames.includes("safeTransferFrom") &&
      contract.stateVars.some((v) => v.name === "_owners" || v.name === "owners"))
  );
}

function detectERC721Invariants(contract, invariants) {
  if (!isERC721Like(contract)) return;

  invariants.push({
    id: "erc721_owner_consistency",
    severity: CRITICAL,
    title: "NFT Ownership Consistency",
    description: "Every token with an owner must be counted in that owner's balance",
    pattern: "ERC721 ownership integrity",
    invariantCode: null,
  });

  invariants.push({
    id: "erc721_no_duplicate_owner",
    severity: CRITICAL,
    title: "No Duplicate Ownership",
    description: "Each tokenId can only have one owner at a time",
    pattern: "ERC721 uniqueness",
    invariantCode: null,
  });
}

// ─── Generic Supply Invariants ───
function detectSupplyInvariants(contract, invariants) {
  // Vault-like: totalDeposited == sum of balances == contract ETH balance
  const hasTotalDeposited = contract.stateVars.some(
    (v) => v.name === "totalDeposited" || v.name === "totalAssets" || v.name === "totalStaked"
  );
  const hasBalances = contract.stateVars.some(
    (v) => v.name === "balances" || v.name === "deposits" || v.name === "stakes"
  );

  if (hasTotalDeposited && hasBalances) {
    const totalVar = contract.stateVars.find(
      (v) => v.name === "totalDeposited" || v.name === "totalAssets" || v.name === "totalStaked"
    );
    const balVar = contract.stateVars.find(
      (v) => v.name === "balances" || v.name === "deposits" || v.name === "stakes"
    );

    invariants.push({
      id: "vault_accounting",
      severity: CRITICAL,
      title: "Vault Accounting Integrity",
      description: `${totalVar.name} must equal sum of all ${balVar.name}`,
      pattern: "Vault accounting",
      invariantCode: `assertEq(vault.${totalVar.name}(), handler.ghost_balanceSum())`,
      ghostVars: [
        {
          name: "ghost_balanceSum",
          type: "uint256",
          trackIn: ["deposit", "withdraw", "stake", "unstake"],
        },
      ],
    });

    // ETH balance solvency
    const hasPayable = contract.functions.some(
      (f) => f.stateMutability === "payable"
    );
    if (hasPayable) {
      invariants.push({
        id: "vault_solvency",
        severity: CRITICAL,
        title: "Contract Solvency",
        description: "Contract ETH balance must be >= totalDeposited (contract can always pay out)",
        pattern: "Vault solvency",
        invariantCode: `assertGe(address(vault).balance, vault.${totalVar.name}())`,
      });
    }
  }
}

// ─── Balance Invariants ───
function detectBalanceInvariants(contract, invariants) {
  for (const fn of contract.functions) {
    // Check for functions that modify balances without proper checks
    const modifiesBalance = fn.stateChanges.some(
      (sc) =>
        sc.target.includes("balance") ||
        sc.target.includes("Balance") ||
        sc.target.includes("deposit")
    );
    if (modifiesBalance && fn.requires.length === 0 && !fn.isConstructor) {
      invariants.push({
        id: `unchecked_balance_mod_${fn.name}`,
        severity: HIGH,
        title: `Unchecked Balance Modification in ${fn.name}()`,
        description: `${fn.name}() modifies balance-related state without require checks`,
        pattern: "Missing validation",
        invariantCode: null,
      });
    }
  }
}

// ─── Access Control ───
function detectAccessControlInvariants(contract, invariants) {
  const ownerVar = contract.stateVars.find(
    (v) => v.name === "owner" || v.name === "_owner" || v.name === "admin"
  );
  if (!ownerVar) return;

  // Check which functions use onlyOwner
  const ownerModifiers = ["onlyOwner", "onlyAdmin", "onlyRole"];
  const protectedFns = contract.functions.filter((f) =>
    f.modifiers.some((m) => ownerModifiers.includes(m))
  );
  const unprotectedStateFns = contract.functions.filter(
    (f) =>
      !f.isConstructor &&
      f.stateChanges.length > 0 &&
      f.visibility === "public" &&
      !f.modifiers.some((m) => ownerModifiers.includes(m))
  );

  invariants.push({
    id: "owner_immutable",
    severity: HIGH,
    title: "Owner Cannot Be Accidentally Changed",
    description: `${ownerVar.name} should only change through authorized functions`,
    pattern: "Access control",
    invariantCode: null,
  });

  if (protectedFns.length > 0) {
    invariants.push({
      id: "access_control_enforced",
      severity: HIGH,
      title: "Access Control Enforcement",
      description: `Protected functions [${protectedFns.map((f) => f.name).join(", ")}] must revert when called by non-owner`,
      pattern: "Access control",
      invariantCode: null,
    });
  }
}

// ─── Pausable ───
function detectPausableInvariants(contract, invariants) {
  const pauseVar = contract.stateVars.find(
    (v) => v.name === "paused" || v.name === "_paused"
  );
  if (!pauseVar) return;

  const pausedFns = contract.functions.filter((f) =>
    f.modifiers.some((m) => m === "whenNotPaused" || m === "whenPaused")
  );

  if (pausedFns.length > 0) {
    invariants.push({
      id: "pausable_enforcement",
      severity: HIGH,
      title: "Pause Mechanism Enforcement",
      description: `When paused, functions [${pausedFns.map((f) => f.name).join(", ")}] must revert`,
      pattern: "Pausable",
      invariantCode: null,
    });
  }
}

// ─── Arithmetic Safety ───
function detectArithmeticInvariants(contract, invariants) {
  // Check for pre-0.8.0 contracts (no built-in overflow protection)
  // In 0.8.0+, overflow is checked by default, but unchecked blocks exist
  for (const fn of contract.functions) {
    if (fn.stateChanges.length > 0) {
      const hasSubtraction = fn.stateChanges.some(
        (sc) => sc.operator === "-=" || sc.operator === "-"
      );
      if (hasSubtraction) {
        invariants.push({
          id: `underflow_${fn.name}`,
          severity: MEDIUM,
          title: `Underflow Protection in ${fn.name}()`,
          description: `${fn.name}() performs subtraction - verify no underflow is possible`,
          pattern: "Arithmetic safety",
          invariantCode: null,
        });
        break; // one per contract is enough
      }
    }
  }
}

// ─── Mapping Consistency ───
function detectMappingConsistency(contract, invariants) {
  // If there's a mapping and a counter/total, they should be consistent
  for (const m of contract.mappings) {
    const relatedTotal = contract.stateVars.find(
      (v) =>
        !v.isMapping &&
        (v.name.toLowerCase().includes("total") ||
          v.name.toLowerCase().includes("count") ||
          v.name.toLowerCase().includes("supply"))
    );
    if (relatedTotal && !invariants.some((i) => i.id.includes("supply_conservation") || i.id.includes("accounting"))) {
      invariants.push({
        id: `mapping_total_consistency_${m.name}_${relatedTotal.name}`,
        severity: MEDIUM,
        title: `Mapping-Total Consistency: ${m.name} vs ${relatedTotal.name}`,
        description: `Sum of all values in ${m.name} should be consistent with ${relatedTotal.name}`,
        pattern: "Data consistency",
        invariantCode: null,
      });
    }
  }
}

// ─── Vulnerability Detection (Feature 3) ───
function detectVulnerabilities(contract) {
  const vulns = [];

  detectReentrancy(contract, vulns);
  detectUncheckedReturn(contract, vulns);
  detectMissingAccessControl(contract, vulns);
  detectFrontRunning(contract, vulns);
  detectDenialOfService(contract, vulns);

  return vulns;
}

function detectReentrancy(contract, vulns) {
  for (const fn of contract.functions) {
    if (fn.externalCalls.length === 0) continue;

    // Check if external call happens before state changes
    for (const call of fn.externalCalls) {
      const callLine = call.loc ? call.loc.start.line : 0;
      const stateChangesAfter = fn.stateChanges.filter(
        (sc) => sc.loc && sc.loc.start.line > callLine
      );

      if (stateChangesAfter.length > 0) {
        vulns.push({
          id: `reentrancy_${fn.name}`,
          severity: CRITICAL,
          title: `Reentrancy in ${fn.name}()`,
          description: `External call (${call.type}) at line ${callLine} occurs BEFORE state updates at line(s) ${stateChangesAfter.map((s) => s.loc.start.line).join(", ")}. An attacker can re-enter this function before state is updated.`,
          pattern: "Reentrancy (SWC-107)",
          function: fn.name,
          line: callLine,
          fix: "Move state changes before the external call (Checks-Effects-Interactions pattern), or use a reentrancy guard",
        });
      }
    }
  }
}

function detectUncheckedReturn(contract, vulns) {
  for (const fn of contract.functions) {
    for (const call of fn.externalCalls) {
      if (call.type === "send") {
        vulns.push({
          id: `unchecked_send_${fn.name}`,
          severity: HIGH,
          title: `Unchecked send() in ${fn.name}()`,
          description: `send() returns bool but failure may not be handled. Use call() with return value check instead.`,
          pattern: "Unchecked Return (SWC-104)",
          function: fn.name,
          line: call.loc ? call.loc.start.line : 0,
          fix: "Replace send() with call() and check the return value, or use transfer()",
        });
      }
    }
  }
}

function detectMissingAccessControl(contract, vulns) {
  const ownerModifiers = ["onlyOwner", "onlyAdmin", "onlyRole", "auth", "authorized"];
  const sensitiveFnNames = ["mint", "burn", "pause", "unpause", "withdraw", "setOwner", "transferOwnership", "upgrade", "selfdestruct", "destroy"];

  for (const fn of contract.functions) {
    if (fn.isConstructor || fn.visibility !== "public") continue;
    const isSensitive = sensitiveFnNames.some((s) => fn.name.toLowerCase().includes(s));
    const hasAccessControl = fn.modifiers.some((m) => ownerModifiers.includes(m));
    const hasRequireOwner = fn.requires.some((r) =>
      r.args.some((a) => a.includes("owner") || a.includes("admin") || a.includes("msg.sender"))
    );

    if (isSensitive && !hasAccessControl && !hasRequireOwner) {
      vulns.push({
        id: `missing_access_${fn.name}`,
        severity: CRITICAL,
        title: `Missing Access Control on ${fn.name}()`,
        description: `${fn.name}() is a sensitive function but has no access control modifier or require check`,
        pattern: "Missing Access Control (SWC-105)",
        function: fn.name,
        line: fn.loc ? fn.loc.start.line : 0,
        fix: `Add an access control modifier (e.g., onlyOwner) to ${fn.name}()`,
      });
    }
  }
}

function detectFrontRunning(contract, vulns) {
  for (const fn of contract.functions) {
    // Detect approve() without increaseAllowance pattern
    if (fn.name === "approve" && fn.params.length >= 2) {
      vulns.push({
        id: "frontrun_approve",
        severity: MEDIUM,
        title: "Front-Running Risk on approve()",
        description: "approve() is vulnerable to front-running. Consider implementing increaseAllowance/decreaseAllowance pattern.",
        pattern: "Front-Running (SWC-114)",
        function: fn.name,
        line: fn.loc ? fn.loc.start.line : 0,
        fix: "Add increaseAllowance() and decreaseAllowance() functions as safer alternatives",
      });
    }
  }
}

function detectDenialOfService(contract, vulns) {
  for (const fn of contract.functions) {
    // Detect push pattern in loops (gas limit DoS)
    if (fn.externalCalls.length > 0) {
      const hasLoop = false; // simplified - would need deeper AST analysis
      // For now, flag functions with multiple external calls
      if (fn.externalCalls.length > 1) {
        vulns.push({
          id: `dos_multiple_calls_${fn.name}`,
          severity: MEDIUM,
          title: `Multiple External Calls in ${fn.name}()`,
          description: `${fn.name}() makes ${fn.externalCalls.length} external calls. If any fails, the entire transaction reverts.`,
          pattern: "DoS with Failed Call (SWC-113)",
          function: fn.name,
          line: fn.loc ? fn.loc.start.line : 0,
          fix: "Consider using a pull-over-push pattern or handling each call's failure independently",
        });
      }
    }
  }
}

// ─── Output Formatting ───
function formatInvariants(invariants, contractName) {
  const lines = [];
  lines.push(chalk.bold.cyan(`\n  Invariant Properties for ${contractName}`));
  lines.push(chalk.gray(`  Found ${invariants.length} properties to verify\n`));

  for (const inv of invariants) {
    const sevColor =
      inv.severity === CRITICAL ? chalk.red.bold :
      inv.severity === HIGH ? chalk.yellow.bold :
      inv.severity === MEDIUM ? chalk.blue.bold :
      chalk.gray.bold;

    lines.push(`  ${sevColor(`[${inv.severity}]`)} ${chalk.white.bold(inv.title)}`);
    lines.push(`    ${chalk.gray(">")} ${inv.description}`);
    lines.push(`    ${chalk.gray("Pattern:")} ${inv.pattern}`);
    if (inv.invariantCode) {
      lines.push(`    ${chalk.gray("Assert:")} ${chalk.green(inv.invariantCode)}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function formatVulnerabilities(vulns, contractName) {
  const lines = [];
  lines.push(chalk.bold.red(`\n  Vulnerability Scan for ${contractName}`));
  lines.push(chalk.gray(`  Found ${vulns.length} potential issues\n`));

  for (const v of vulns) {
    const sevColor =
      v.severity === CRITICAL ? chalk.red.bold :
      v.severity === HIGH ? chalk.yellow.bold :
      v.severity === MEDIUM ? chalk.blue.bold :
      chalk.gray.bold;

    lines.push(`  ${sevColor(`[${v.severity}]`)} ${chalk.white.bold(v.title)}`);
    if (v.line) lines.push(`    ${chalk.gray("Line:")} ${v.line}`);
    lines.push(`    ${chalk.gray(">")} ${v.description}`);
    lines.push(`    ${chalk.gray("Pattern:")} ${v.pattern}`);
    lines.push(`    ${chalk.green("Fix:")} ${v.fix}`);
    lines.push("");
  }
  return lines.join("\n");
}

module.exports = {
  discoverInvariants,
  detectVulnerabilities,
  formatInvariants,
  formatVulnerabilities,
  CRITICAL, HIGH, MEDIUM, LOW,
};
