const path = require("path");
const fs = require("fs");

/**
 * Generate Foundry invariant test files from analysis results
 */
function generateFoundryTests(contract, invariants, vulns, outputDir) {
  const files = [];

  // Generate invariant test file
  if (invariants.length > 0) {
    const invTest = generateInvariantTest(contract, invariants);
    const invPath = path.join(outputDir, `${contract.name}.invariant.t.sol`);
    fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(invPath, invTest);
    files.push(invPath);
  }

  // Generate vulnerability-targeted test file
  if (vulns.length > 0) {
    const vulnTest = generateVulnTest(contract, vulns);
    const vulnPath = path.join(outputDir, `${contract.name}.vuln.t.sol`);
    fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(vulnPath, vulnTest);
    files.push(vulnPath);
  }

  return files;
}

function generateInvariantTest(contract, invariants) {
  const name = contract.name;
  const lines = [];

  lines.push(`// SPDX-License-Identifier: MIT`);
  lines.push(`pragma solidity ^0.8.20;`);
  lines.push(``);
  lines.push(`import "forge-std/Test.sol";`);
  lines.push(`// TODO: Update this import path to match your project structure`);
  lines.push(`import "../src/${name}.sol";`);
  lines.push(``);

  // ─── Handler Contract ───
  lines.push(generateHandler(contract, invariants));
  lines.push(``);

  // ─── Invariant Test Contract ───
  lines.push(`contract ${name}InvariantTest is Test {`);
  lines.push(`    ${name} public target;`);
  lines.push(`    ${name}Handler public handler;`);
  lines.push(``);

  // setUp
  lines.push(`    function setUp() public {`);
  lines.push(...getSetupLines(contract));
  lines.push(`        handler = new ${name}Handler(target);`);
  lines.push(`        targetContract(address(handler));`);
  lines.push(`    }`);
  lines.push(``);

  // Generate invariant functions
  for (const inv of invariants) {
    lines.push(generateInvariantFunction(contract, inv));
    lines.push(``);
  }

  lines.push(`}`);
  return lines.join("\n");
}

function generateHandler(contract, invariants) {
  const name = contract.name;
  const lines = [];

  // Collect all ghost variables needed
  const ghostVars = new Map();
  for (const inv of invariants) {
    if (inv.ghostVars) {
      for (const g of inv.ghostVars) {
        ghostVars.set(g.name, g);
      }
    }
  }

  lines.push(`contract ${name}Handler is Test {`);
  lines.push(`    ${name} public target;`);
  lines.push(``);

  // Ghost variables for tracking
  lines.push(`    // Ghost variables for invariant tracking`);
  for (const [gName, g] of ghostVars) {
    lines.push(`    ${g.type} public ${gName};`);
  }
  lines.push(`    uint256 public callCount;`);
  lines.push(``);

  // Actor tracking
  lines.push(`    // Actor management`);
  lines.push(`    address[] public actors;`);
  lines.push(`    address internal currentActor;`);
  lines.push(``);
  lines.push(`    modifier useActor(uint256 actorSeed) {`);
  lines.push(`        if (actors.length == 0) {`);
  lines.push(`            actors.push(address(0x1));`);
  lines.push(`            actors.push(address(0x2));`);
  lines.push(`            actors.push(address(0x3));`);
  lines.push(`        }`);
  lines.push(`        currentActor = actors[actorSeed % actors.length];`);
  lines.push(`        vm.startPrank(currentActor);`);
  lines.push(`        _;`);
  lines.push(`        vm.stopPrank();`);
  lines.push(`    }`);
  lines.push(``);

  // Constructor
  lines.push(`    constructor(${name} _target) {`);
  lines.push(`        target = _target;`);
  lines.push(`    }`);
  lines.push(``);

  // Generate handler functions for each public/external function
  for (const fn of contract.functions) {
    if (fn.isConstructor || fn.visibility === "internal" || fn.visibility === "private") continue;
    lines.push(generateHandlerFunction(contract, fn, ghostVars));
    lines.push(``);
  }

  lines.push(`}`);
  return lines.join("\n");
}

function generateHandlerFunction(contract, fn, ghostVars) {
  const lines = [];
  const params = [];
  const callArgs = [];
  const boundingLines = [];

  // Add actorSeed for prank
  params.push("uint256 actorSeed");

  for (const p of fn.params) {
    params.push(`${mapType(p.type)} ${p.name}`);

    // Add bounding for common types
    if (p.type === "uint256" || p.type === "uint128" || p.type === "uint64") {
      boundingLines.push(`        ${p.name} = bound(${p.name}, 0, type(uint96).max);`);
    }
    if (p.type === "address") {
      boundingLines.push(`        ${p.name} = address(uint160(bound(uint256(uint160(${p.name})), 1, type(uint160).max)));`);
    }
    callArgs.push(p.name);
  }

  const modStr = fn.stateMutability === "payable" ? " useActor(actorSeed)" : " useActor(actorSeed)";
  lines.push(`    function ${fn.name}(${params.join(", ")}) public${modStr} {`);
  lines.push(`        callCount++;`);

  // Add bounding
  for (const bl of boundingLines) {
    lines.push(bl);
  }

  // Add payable handling
  if (fn.stateMutability === "payable") {
    lines.push(`        uint256 value = bound(actorSeed, 0, 10 ether);`);
    lines.push(`        deal(currentActor, value);`);
  }

  // Ghost variable tracking
  for (const [gName, g] of ghostVars) {
    if (g.trackIn && g.trackIn.includes(fn.name)) {
      if (gName.includes("balanceSum") || gName.includes("totalMinted")) {
        lines.push(`        // Track ${gName} - update based on actual state change`);
      }
    }
  }

  // Try-catch wrapper for the actual call
  const valueStr = fn.stateMutability === "payable" ? "{value: value}" : "";
  if (callArgs.length > 0) {
    lines.push(`        try target.${fn.name}${valueStr}(${callArgs.join(", ")}) {`);
  } else {
    lines.push(`        try target.${fn.name}${valueStr}() {`);
  }
  lines.push(`            // Call succeeded`);
  lines.push(`        } catch {`);
  lines.push(`            // Call reverted - expected for invalid inputs`);
  lines.push(`        }`);
  lines.push(`    }`);

  return lines.join("\n");
}

function generateInvariantFunction(contract, inv) {
  const lines = [];
  const fnName = `invariant_${inv.id}`;

  lines.push(`    /// ${inv.severity}: ${inv.title}`);
  lines.push(`    /// ${inv.description}`);
  lines.push(`    function ${fnName}() public view {`);

  if (inv.invariantCode) {
    // Replace contract-specific names with 'target'
    let code = inv.invariantCode;
    const lcName = contract.name.toLowerCase();
    code = code.replace(new RegExp(`\\b${lcName}\\.`, "g"), "target.");
    code = code.replace(new RegExp(`\\b${contract.name}\\.`, "g"), "target.");
    // Also handle address(contractName) pattern
    code = code.replace(new RegExp(`address\\(${lcName}\\)`, "g"), "address(target)");
    code = code.replace(new RegExp(`address\\(${contract.name}\\)`, "g"), "address(target)");
    lines.push(`        ${code};`);
  } else {
    // Generate appropriate assertion based on invariant type
    lines.push(`        // TODO: Implement this invariant check`);
    lines.push(`        // ${inv.description}`);

    if (inv.id.includes("zero_address")) {
      lines.push(`        // Verify: transfer to address(0) should always revert`);
      lines.push(`        // This is tested via the handler's bounded address inputs`);
    } else if (inv.id.includes("access_control")) {
      lines.push(`        // Verify: protected functions revert for non-owners`);
    } else if (inv.id.includes("pausable")) {
      lines.push(`        // Verify: paused state blocks protected functions`);
    }
  }

  lines.push(`    }`);
  return lines.join("\n");
}

function getSetupLines(contract) {
  const lines = [];
  const constructorFn = contract.functions.find((f) => f.isConstructor);

  if (constructorFn && constructorFn.params.length > 0) {
    const args = constructorFn.params.map((p) => {
      if (p.type === "string") return `"Test"`;
      if (p.type === "uint256") return `1000000`;
      if (p.type === "uint8") return `18`;
      if (p.type === "address") return `address(this)`;
      if (p.type === "bool") return `true`;
      return `0`;
    });
    lines.push(`        target = new ${contract.name}(${args.join(", ")});`);
  } else {
    lines.push(`        target = new ${contract.name}();`);
  }

  return lines;
}

// ─── Vulnerability Test Generation ───
function generateVulnTest(contract, vulns) {
  const name = contract.name;
  const lines = [];

  lines.push(`// SPDX-License-Identifier: MIT`);
  lines.push(`pragma solidity ^0.8.20;`);
  lines.push(``);
  lines.push(`import "forge-std/Test.sol";`);
  lines.push(`// TODO: Update this import path to match your project structure`);
  lines.push(`import "../src/${name}.sol";`);
  lines.push(``);

  // Generate attacker contract for reentrancy tests
  const hasReentrancy = vulns.some((v) => v.id.includes("reentrancy"));
  if (hasReentrancy) {
    lines.push(generateAttackerContract(contract, vulns));
    lines.push(``);
  }

  lines.push(`contract ${name}VulnTest is Test {`);
  lines.push(`    ${name} public target;`);
  if (hasReentrancy) {
    lines.push(`    ${name}Attacker public attacker;`);
  }
  lines.push(`    address public owner = address(this);`);
  lines.push(`    address public user1 = address(0x1);`);
  lines.push(`    address public user2 = address(0x2);`);
  lines.push(``);

  // setUp
  lines.push(`    function setUp() public {`);
  const constructorFn = contract.functions.find((f) => f.isConstructor);
  if (constructorFn && constructorFn.params.length > 0) {
    const args = constructorFn.params.map((p) => {
      if (p.type === "string") return `"Test"`;
      if (p.type === "uint256") return `1000000`;
      if (p.type === "uint8") return `18`;
      if (p.type === "address") return `address(this)`;
      return `0`;
    });
    lines.push(`        target = new ${name}(${args.join(", ")});`);
  } else {
    lines.push(`        target = new ${name}();`);
  }
  if (hasReentrancy) {
    lines.push(`        attacker = new ${name}Attacker(target);`);
  }
  lines.push(`    }`);
  lines.push(``);

  // Generate test for each vulnerability
  for (const v of vulns) {
    lines.push(generateVulnTestFunction(contract, v));
    lines.push(``);
  }

  lines.push(`}`);
  return lines.join("\n");
}

function generateAttackerContract(contract, vulns) {
  const name = contract.name;
  const reentrancyVulns = vulns.filter((v) => v.id.includes("reentrancy"));
  const lines = [];

  lines.push(`contract ${name}Attacker {`);
  lines.push(`    ${name} public target;`);
  lines.push(`    uint256 public attackCount;`);
  lines.push(`    uint256 public maxAttacks = 3;`);
  lines.push(``);
  lines.push(`    constructor(${name} _target) {`);
  lines.push(`        target = _target;`);
  lines.push(`    }`);
  lines.push(``);

  for (const v of reentrancyVulns) {
    lines.push(`    function attack_${v.function}() external payable {`);
    lines.push(`        target.${v.function}${getAttackArgs(contract, v.function)};`);
    lines.push(`    }`);
    lines.push(``);
  }

  lines.push(`    receive() external payable {`);
  lines.push(`        if (attackCount < maxAttacks) {`);
  lines.push(`            attackCount++;`);
  for (const v of reentrancyVulns) {
    lines.push(`            try target.${v.function}${getAttackArgs(contract, v.function)} {} catch {}`);
  }
  lines.push(`        }`);
  lines.push(`    }`);
  lines.push(`}`);

  return lines.join("\n");
}

function getAttackArgs(contract, fnName) {
  const fn = contract.functions.find((f) => f.name === fnName);
  if (!fn) return "()";

  if (fn.params.length === 0) {
    return fn.stateMutability === "payable" ? "{value: msg.value}()" : "()";
  }

  const args = fn.params.map((p) => {
    if (p.type === "uint256") return "address(this).balance";
    if (p.type === "address") return "address(this)";
    return "0";
  });

  const valueStr = fn.stateMutability === "payable" ? "{value: msg.value}" : "";
  return `${valueStr}(${args.join(", ")})`;
}

function generateVulnTestFunction(contract, vuln) {
  const lines = [];

  if (vuln.id.includes("reentrancy")) {
    lines.push(`    /// @notice Test: ${vuln.title}`);
    lines.push(`    /// ${vuln.description}`);
    lines.push(`    function test_${vuln.id}() public {`);
    lines.push(`        // Setup: Give the contract some ETH`);
    lines.push(`        deal(address(user1), 10 ether);`);
    lines.push(`        vm.startPrank(user1);`);

    // Find deposit function
    const depositFn = contract.functions.find(
      (f) => f.name === "deposit" || f.stateMutability === "payable"
    );
    if (depositFn) {
      lines.push(`        target.${depositFn.name}{value: 5 ether}();`);
    }
    lines.push(`        vm.stopPrank();`);
    lines.push(``);
    lines.push(`        // Attack: Attacker deposits and tries to re-enter`);
    lines.push(`        deal(address(attacker), 2 ether);`);
    lines.push(`        uint256 contractBalBefore = address(target).balance;`);
    lines.push(``);
    lines.push(`        // If reentrancy exists, attacker drains more than deposited`);
    lines.push(`        // This test should FAIL if the vulnerability exists`);
    lines.push(`        // (meaning the contract IS vulnerable)`);
    lines.push(`        vm.expectRevert(); // Remove this if you want to see the attack succeed`);
    lines.push(`        attacker.attack_${vuln.function}();`);
    lines.push(``);
    lines.push(`        // Verify contract solvency`);
    lines.push(`        // assertGe(address(target).balance, contractBalBefore - 2 ether);`);
    lines.push(`    }`);
  } else if (vuln.id.includes("missing_access")) {
    lines.push(`    /// @notice Test: ${vuln.title}`);
    lines.push(`    /// ${vuln.description}`);
    lines.push(`    function test_${vuln.id}() public {`);
    lines.push(`        // Non-owner should NOT be able to call ${vuln.function}()`);
    lines.push(`        vm.startPrank(user1);`);
    lines.push(`        vm.expectRevert();`);
    lines.push(`        // TODO: Call target.${vuln.function}() with appropriate args`);
    lines.push(`        // target.${vuln.function}();`);
    lines.push(`        vm.stopPrank();`);
    lines.push(`    }`);
  } else if (vuln.id.includes("frontrun")) {
    lines.push(`    /// @notice Test: ${vuln.title}`);
    lines.push(`    /// ${vuln.description}`);
    lines.push(`    function test_${vuln.id}() public {`);
    lines.push(`        // Demonstrate front-running risk with approve()`);
    lines.push(`        // 1. User approves spender for 100 tokens`);
    lines.push(`        // 2. User wants to change approval to 50`);
    lines.push(`        // 3. Spender front-runs and spends 100 before the change`);
    lines.push(`        // 4. New approval of 50 goes through`);
    lines.push(`        // 5. Spender spends 50 more = 150 total (should be max 100)`);
    lines.push(`        // TODO: Implement with actual token balances`);
    lines.push(`    }`);
  } else {
    lines.push(`    /// @notice Test: ${vuln.title}`);
    lines.push(`    /// ${vuln.description}`);
    lines.push(`    function test_${vuln.id}() public {`);
    lines.push(`        // TODO: Implement test for ${vuln.pattern}`);
    lines.push(`        // Fix suggestion: ${vuln.fix}`);
    lines.push(`    }`);
  }

  return lines.join("\n");
}

function mapType(solType) {
  const typeMap = {
    address: "address",
    uint256: "uint256",
    uint128: "uint128",
    uint64: "uint64",
    uint32: "uint32",
    uint8: "uint8",
    int256: "int256",
    bool: "bool",
    string: "string memory",
    bytes: "bytes memory",
    bytes32: "bytes32",
  };
  return typeMap[solType] || solType;
}

module.exports = { generateFoundryTests };
