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

  // Collect ghost vars to know what needs initialization
  const ghostVars = new Map();
  for (const inv of invariants) {
    if (inv.ghostVars) {
      for (const g of inv.ghostVars) {
        ghostVars.set(g.name, g);
      }
    }
  }

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

  // Initialize ghost_balanceSum for ERC20 tokens (constructor mints initial supply)
  if (ghostVars.has("ghost_balanceSum")) {
    const supplyVar = contract.stateVars.find(
      (v) => v.name === "totalSupply" || v.name === "_totalSupply"
    );
    if (supplyVar) {
      lines.push(`        // Initialize ghost to match initial supply from constructor`);
      lines.push(`        handler.initGhostBalanceSum(target.${supplyVar.name}());`);
    }
  }
  if (ghostVars.has("ghost_totalMinted")) {
    const supplyVar = contract.stateVars.find(
      (v) => v.name === "totalSupply" || v.name === "_totalSupply"
    );
    if (supplyVar) {
      lines.push(`        handler.initGhostTotalMinted(target.${supplyVar.name}());`);
    }
  }

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

  // Ghost variable initializers (called from setUp for initial state)
  if (ghostVars.has("ghost_balanceSum")) {
    lines.push(`    function initGhostBalanceSum(uint256 _val) external {`);
    lines.push(`        ghost_balanceSum = _val;`);
    lines.push(`    }`);
    lines.push(``);
  }
  if (ghostVars.has("ghost_totalMinted")) {
    lines.push(`    function initGhostTotalMinted(uint256 _val) external {`);
    lines.push(`        ghost_totalMinted = _val;`);
    lines.push(`    }`);
    lines.push(``);
  }

  // Generate handler functions for each public/external function
  for (const fn of contract.functions) {
    if (fn.isConstructor || fn.visibility === "internal" || fn.visibility === "private") continue;
    // Skip special functions that can't be called directly
    if (fn.name === "receive" || fn.name === "fallback" || fn.name === "") continue;
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

  // Collect ghost update lines for this function
  const ghostUpdates = [];
  for (const [gName, g] of ghostVars) {
    if (g.trackIn && g.trackIn.includes(fn.name)) {
      const update = getGhostUpdate(gName, fn);
      if (update) ghostUpdates.push(update);
    }
  }

  // Try-catch wrapper for the actual call
  const valueStr = fn.stateMutability === "payable" ? "{value: value}" : "";
  if (callArgs.length > 0) {
    lines.push(`        try target.${fn.name}${valueStr}(${callArgs.join(", ")}) {`);
  } else {
    lines.push(`        try target.${fn.name}${valueStr}() {`);
  }
  // Update ghost variables on success
  if (ghostUpdates.length > 0) {
    for (const u of ghostUpdates) {
      lines.push(`            ${u}`);
    }
  }
  lines.push(`        } catch {}`);
  lines.push(`    }`);

  return lines.join("\n");
}

function getGhostUpdate(gName, fn) {
  const name = fn.name.toLowerCase();
  const isPayable = fn.stateMutability === "payable";
  const amountParam = fn.params.find(
    (p) => p.type === "uint256" && (p.name === "amount" || p.name === "_amount" || p.name === "value")
  );
  const amountVar = amountParam ? amountParam.name : null;

  if (gName === "ghost_balanceSum") {
    // Payable deposit/stake: add the ETH value sent
    if (isPayable) return `ghost_balanceSum += value;`;
    // Withdraw/unstake/burn: subtract the amount
    if (name.includes("withdraw") || name.includes("unstake") || name.includes("burn")) {
      return amountVar ? `ghost_balanceSum -= ${amountVar};` : null;
    }
    // Mint: add the amount
    if (name.includes("mint") || name === "_mint") {
      return amountVar ? `ghost_balanceSum += ${amountVar};` : null;
    }
    // Transfer: no change to total sum
    return null;
  }

  if (gName === "ghost_totalMinted") {
    if (name.includes("mint")) {
      return amountVar ? `ghost_totalMinted += ${amountVar};` : null;
    }
    return null;
  }

  if (gName === "ghost_senderDecrease") {
    if (name.includes("transfer")) {
      return amountVar ? `ghost_senderDecrease += ${amountVar};` : null;
    }
    return null;
  }

  if (gName === "ghost_receiverIncrease") {
    if (name.includes("transfer")) {
      return amountVar ? `ghost_receiverIncrease += ${amountVar};` : null;
    }
    return null;
  }

  return null;
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
      if (p.type === "address") return `address(this)`;
      if (p.type === "bool") return `true`;
      if (p.type === "uint8") return `18`;
      if (p.type === "bytes32") return `bytes32(0)`;
      if (p.type === "bytes4") return `bytes4(0)`;
      if (p.type.startsWith("uint")) return `1000000`;
      if (p.type.startsWith("int")) return `int256(0)`;
      if (p.type === "bytes") return `""`;
      if (p.type.endsWith("[]")) return `new ${p.type}(0)`;
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
      if (p.type === "address") return `address(this)`;
      if (p.type === "bool") return `true`;
      if (p.type === "uint8") return `18`;
      if (p.type === "bytes32") return `bytes32(0)`;
      if (p.type === "bytes4") return `bytes4(0)`;
      if (p.type.startsWith("uint")) return `1000000`;
      if (p.type.startsWith("int")) return `int256(0)`;
      if (p.type === "bytes") return `""`;
      if (p.type.endsWith("[]")) return `new ${p.type}(0)`;
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

  // Find the deposit/stake function for the attacker to use
  const depositFn = contract.functions.find(
    (f) => (f.name === "deposit" || f.name === "stake") && f.stateMutability === "payable"
  );
  const depositCall = depositFn ? `target.${depositFn.name}` : null;

  lines.push(`contract ${name}Attacker {`);
  lines.push(`    ${name} public target;`);
  lines.push(`    uint256 public attackCount;`);
  lines.push(`    uint256 public maxAttacks = 3;`);
  lines.push(`    uint256 public depositAmount;`);
  lines.push(``);
  lines.push(`    constructor(${name} _target) {`);
  lines.push(`        target = _target;`);
  lines.push(`    }`);
  lines.push(``);

  for (const v of reentrancyVulns) {
    lines.push(`    function attack_${v.function}() external payable {`);
    if (depositCall) {
      lines.push(`        depositAmount = msg.value;`);
      lines.push(`        ${depositCall}{value: msg.value}();`);
    }
    lines.push(`        target.${v.function}${getAttackArgsFixed(contract, v.function)};`);
    lines.push(`    }`);
    lines.push(``);
  }

  lines.push(`    receive() external payable {`);
  lines.push(`        if (attackCount < maxAttacks) {`);
  lines.push(`            attackCount++;`);
  for (const v of reentrancyVulns) {
    lines.push(`            try target.${v.function}${getAttackArgsFixed(contract, v.function)} {} catch {}`);
  }
  lines.push(`        }`);
  lines.push(`    }`);
  lines.push(`}`);

  return lines.join("\n");
}

function getAttackArgsFixed(contract, fnName) {
  const fn = contract.functions.find((f) => f.name === fnName);
  if (!fn) return "()";

  if (fn.params.length === 0) {
    return fn.stateMutability === "payable" ? "{value: depositAmount}()" : "()";
  }

  const args = fn.params.map((p) => {
    if (p.type === "uint256") return "depositAmount";
    if (p.type === "address") return "address(this)";
    return "0";
  });

  const valueStr = fn.stateMutability === "payable" ? "{value: depositAmount}" : "";
  return `${valueStr}(${args.join(", ")})`;
}


function generateVulnTestFunction(contract, vuln) {
  const lines = [];

  if (vuln.id.includes("reentrancy")) {
    lines.push(`    /// @notice Test: ${vuln.title}`);
    lines.push(`    /// ${vuln.description}`);
    lines.push(`    function test_${vuln.id}() public {`);
    lines.push(`        // Setup: Give user1 some ETH and deposit into the contract`);
    lines.push(`        deal(address(user1), 10 ether);`);
    lines.push(`        vm.startPrank(user1);`);

    // Find deposit function
    const depositFn = contract.functions.find(
      (f) => (f.name === "deposit" || f.name === "stake") && f.stateMutability === "payable"
    );
    if (depositFn) {
      lines.push(`        target.${depositFn.name}{value: 5 ether}();`);
    }
    lines.push(`        vm.stopPrank();`);
    lines.push(``);
    lines.push(`        // Attack: Attacker deposits 1 ETH, then exploits reentrancy to drain more`);
    lines.push(`        deal(address(attacker), 1 ether);`);
    lines.push(`        uint256 contractBalBefore = address(target).balance;`);
    lines.push(`        attacker.attack_${vuln.function}{value: 1 ether}();`);
    lines.push(``);
    lines.push(`        // If vulnerable: attacker drained more than their 1 ETH deposit`);
    lines.push(`        uint256 attackerBal = address(attacker).balance;`);
    lines.push(`        // This assertion PASSES if the contract IS vulnerable (attacker profits)`);
    lines.push(`        // Fix the contract, then this test should FAIL`);
    lines.push(`        assertGt(attackerBal, 1 ether, "Reentrancy: attacker should have drained extra ETH");`);
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
    int128: "int128",
    bool: "bool",
    string: "string memory",
    bytes: "bytes memory",
    bytes32: "bytes32",
    bytes4: "bytes4",
  };
  if (typeMap[solType]) return typeMap[solType];
  // Array types always need memory qualifier
  if (solType.endsWith("[]")) return `${solType} memory`;
  // Mapping types (shouldn't appear in params but handle gracefully)
  if (solType.startsWith("mapping")) return solType;
  // User-defined types (structs, enums) need memory if they're reference types
  // For safety, add memory to unknown types that aren't value types
  return solType;
}

module.exports = { generateFoundryTests };
