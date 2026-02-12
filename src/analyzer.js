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

  const lcName = contract.name.toLowerCase();
  invariants.push({
    id: "erc20_supply_conservation",
    severity: CRITICAL,
    title: "Total Supply Conservation",
    description: `${supplyVar.name} must always equal the sum of all ${balVar.name}`,
    pattern: "ERC20 supply integrity",
    invariantCode: `assertEq(${lcName}.${supplyVar.name}(), handler.ghost_balanceSum())`,
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
    invariantCode: `assertLe(${lcName}.${supplyVar.name}(), handler.ghost_totalMinted())`,
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

    const lcName = contract.name.toLowerCase();
    invariants.push({
      id: "vault_accounting",
      severity: CRITICAL,
      title: "Vault Accounting Integrity",
      description: `${totalVar.name} must equal sum of all ${balVar.name}`,
      pattern: "Vault accounting",
      invariantCode: `assertEq(${lcName}.${totalVar.name}(), handler.ghost_balanceSum())`,
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
        invariantCode: `assertGe(address(${lcName}).balance, ${lcName}.${totalVar.name}())`,
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
    if (modifiesBalance && fn.requires.length === 0 && !fn.isConstructor &&
        fn.visibility !== "internal" && fn.visibility !== "private") {
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
      (f.visibility === "public" || f.visibility === "external") &&
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
      // Only flag send() when return value is not captured (unchecked)
      if (call.type === "send" && !call.isReturnCaptured) {
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
    if (fn.isConstructor || (fn.visibility !== "public" && fn.visibility !== "external")) continue;
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

// ─── Gas Optimization Detection ───
function detectGasIssues(contract) {
  const issues = [];
  detectNonIndexedEvents(contract, issues);
  detectImmutableCandidates(contract, issues);
  detectCalldataParams(contract, issues);
  return issues;
}

function detectNonIndexedEvents(contract, issues) {
  for (const event of contract.events) {
    const indexedCount = event.params.filter((p) => p.isIndexed).length;
    const indexable = event.params.filter(
      (p) =>
        !p.isIndexed &&
        ["address", "uint256", "uint128", "uint64", "uint32", "uint16", "uint8",
         "int256", "int128", "bytes32", "bool"].includes(p.type)
    );
    if (indexable.length > 0 && indexedCount < 3) {
      const canIndex = Math.min(indexable.length, 3 - indexedCount);
      issues.push({
        id: `gas_event_index_${event.name}`,
        title: `Add indexed to ${event.name} event parameters`,
        description: `${event.name} has ${indexable.length} param(s) that could be indexed for cheaper log filtering`,
        savings: "~375 gas saved per indexed param when filtering logs",
        fix: `Add indexed keyword to: ${indexable.slice(0, canIndex).map((p) => p.name).join(", ")}`,
      });
    }
  }
}

function detectImmutableCandidates(contract, issues) {
  const ctorFn = contract.functions.find((f) => f.isConstructor);
  if (!ctorFn) return;
  const otherFns = contract.functions.filter((f) => !f.isConstructor);

  for (const sv of contract.stateVars) {
    if (sv.isDeclaredConst || sv.isImmutable || sv.isMapping) continue;
    if (sv.typeName.startsWith("mapping") || sv.typeName.endsWith("[]")) continue;
    // string and bytes cannot be immutable in most Solidity versions
    if (sv.typeName === "string" || sv.typeName === "bytes") continue;

    const setInCtor = ctorFn.stateChanges.some((sc) => sc.target === sv.name);
    const modifiedElsewhere = otherFns.some((fn) =>
      fn.stateChanges.some((sc) => sc.target === sv.name)
    );

    if (setInCtor && !modifiedElsewhere) {
      issues.push({
        id: `gas_immutable_${sv.name}`,
        title: `Use immutable for ${sv.name}`,
        description: `${sv.name} is only set in constructor and never modified afterward`,
        savings: "~2100 gas saved per read (SLOAD replaced by code copy)",
        fix: `Declare as: ${sv.typeName} public immutable ${sv.name}`,
      });
    }
  }
}

function detectCalldataParams(contract, issues) {
  for (const fn of contract.functions) {
    // Only external functions can safely use calldata (public may be called internally)
    if (fn.visibility !== "external") continue;
    for (const param of fn.params) {
      if (param.type.endsWith("[]") || param.type === "string" || param.type === "bytes") {
        issues.push({
          id: `gas_calldata_${fn.name}_${param.name}`,
          title: `Use calldata for ${param.name} in ${fn.name}()`,
          description: `${param.name} (${param.type}) can use calldata instead of memory`,
          savings: "~600+ gas saved (avoids memory copy)",
          fix: `Change parameter to: ${param.type} calldata ${param.name}`,
        });
      }
    }
  }
}

// ─── Security Score ───
function calculateSecurityScore(vulns) {
  let score = 100;
  const deductions = [];

  for (const v of vulns) {
    let pts = 0;
    if (v.severity === CRITICAL) pts = 25;
    else if (v.severity === HIGH) pts = 15;
    else if (v.severity === MEDIUM) pts = 8;
    else if (v.severity === LOW) pts = 3;

    score -= pts;
    deductions.push({ pts, title: v.title, severity: v.severity });
  }

  score = Math.max(0, Math.min(100, score));

  let grade;
  if (score >= 95) grade = "A+";
  else if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";
  else grade = "F";

  return { score, grade, deductions };
}

function formatSecurityScore(scoreData) {
  const { score, grade, deductions } = scoreData;

  const gradeColor =
    grade.startsWith("A") ? chalk.green.bold :
    grade === "B" ? chalk.cyan.bold :
    grade === "C" ? chalk.yellow.bold :
    grade === "D" ? chalk.red.bold :
    chalk.red.bold;

  const barLen = 30;
  const filled = Math.round((score / 100) * barLen);
  const barColor = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red;
  const bar = barColor("█".repeat(filled)) + chalk.gray("░".repeat(barLen - filled));

  const lines = [];
  lines.push("");
  lines.push(`  ${chalk.bold.white("Security Score:")} ${gradeColor(grade)} ${chalk.white(`(${score}/100)`)}`);
  lines.push(`  ${bar}`);

  if (deductions.length > 0) {
    lines.push("");
    for (const d of deductions) {
      const sevColor =
        d.severity === CRITICAL ? chalk.red :
        d.severity === HIGH ? chalk.yellow :
        d.severity === MEDIUM ? chalk.blue :
        chalk.gray;
      lines.push(`    ${sevColor(`-${d.pts}`)}  ${d.title}`);
    }
  } else {
    lines.push(`  ${chalk.green("No vulnerabilities detected!")}`);
  }

  return lines.join("\n");
}

function formatGasIssues(issues, contractName) {
  const lines = [];
  lines.push(chalk.bold.magenta(`\n  Gas Optimization for ${contractName}`));
  lines.push(chalk.gray(`  Found ${issues.length} optimization opportunities\n`));

  for (const issue of issues) {
    lines.push(`  ${chalk.magenta.bold("[GAS]")} ${chalk.white.bold(issue.title)}`);
    lines.push(`    ${chalk.gray(">")} ${issue.description}`);
    lines.push(`    ${chalk.gray("Savings:")} ${chalk.green(issue.savings)}`);
    lines.push(`    ${chalk.green("Fix:")} ${issue.fix}`);
    lines.push("");
  }
  return lines.join("\n");
}

// ─── Markdown Report ───
function generateMarkdownReport(contractName, invariants, vulns, gasIssues, scoreData) {
  const lines = [];
  const date = new Date().toISOString().split("T")[0];

  lines.push(`# Sol-Shield Security Report`);
  lines.push("");
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Contract | ${contractName} |`);
  lines.push(`| Date | ${date} |`);
  lines.push(`| Security Score | **${scoreData.grade}** (${scoreData.score}/100) |`);
  lines.push(`| Invariants | ${invariants.length} |`);
  lines.push(`| Vulnerabilities | ${vulns.length} |`);
  lines.push(`| Gas Optimizations | ${gasIssues.length} |`);
  lines.push("");

  // Vulnerabilities
  if (vulns.length > 0) {
    lines.push(`## Vulnerabilities`);
    lines.push("");
    lines.push(`| Severity | Issue | Line | Pattern | Fix |`);
    lines.push(`|----------|-------|------|---------|-----|`);
    for (const v of vulns) {
      lines.push(`| ${v.severity} | ${v.title} | ${v.line || "-"} | ${v.pattern} | ${v.fix} |`);
    }
    lines.push("");
  }

  // Invariants
  if (invariants.length > 0) {
    lines.push(`## Invariant Properties`);
    lines.push("");
    lines.push(`| Severity | Property | Pattern | Assertion |`);
    lines.push(`|----------|----------|---------|-----------|`);
    for (const inv of invariants) {
      lines.push(`| ${inv.severity} | ${inv.title} | ${inv.pattern} | ${inv.invariantCode || "Manual check needed"} |`);
    }
    lines.push("");
  }

  // Gas
  if (gasIssues.length > 0) {
    lines.push(`## Gas Optimizations`);
    lines.push("");
    lines.push(`| Issue | Savings | Fix |`);
    lines.push(`|-------|---------|-----|`);
    for (const g of gasIssues) {
      lines.push(`| ${g.title} | ${g.savings} | ${g.fix} |`);
    }
    lines.push("");
  }

  // Score breakdown
  if (scoreData.deductions.length > 0) {
    lines.push(`## Score Breakdown`);
    lines.push("");
    lines.push(`Starting score: 100`);
    lines.push("");
    for (const d of scoreData.deductions) {
      lines.push(`- **-${d.pts}** ${d.severity}: ${d.title}`);
    }
    lines.push("");
    lines.push(`**Final Score: ${scoreData.score}/100 (${scoreData.grade})**`);
    lines.push("");
  }

  lines.push("---");
  lines.push(`*Generated by [sol-shield](https://github.com/xka0085-byte/sol-shield) v0.1.0*`);

  return lines.join("\n");
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
  detectGasIssues,
  calculateSecurityScore,
  formatInvariants,
  formatVulnerabilities,
  formatGasIssues,
  formatSecurityScore,
  generateMarkdownReport,
  CRITICAL, HIGH, MEDIUM, LOW,
};
