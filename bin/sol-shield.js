#!/usr/bin/env node

const { Command } = require("commander");
const chalk = require("chalk");
const path = require("path");
const fs = require("fs");
const { parseFile } = require("../src/parser");
const {
  discoverInvariants,
  detectVulnerabilities,
  detectGasIssues,
  calculateSecurityScore,
  formatInvariants,
  formatVulnerabilities,
  formatGasIssues,
  formatSecurityScore,
  generateMarkdownReport,
} = require("../src/analyzer");
const { generateFoundryTests } = require("../src/generator");

const program = new Command();

program
  .name("sol-shield")
  .description(
    "Smart contract security test advisor - discover invariants, detect vulnerabilities, generate Foundry tests"
  )
  .version("0.1.0");

// ─── analyze command ───
program
  .command("analyze")
  .description("Analyze a Solidity file: discover invariants and detect vulnerabilities")
  .argument("<file>", "Path to Solidity file")
  .option("-o, --output <dir>", "Output directory for reports", ".")
  .option("-f, --format <type>", "Output format: terminal (default) or md", "terminal")
  .action((file, opts) => {
    run("analyze", file, opts);
  });

// ─── generate command ───
program
  .command("generate")
  .description("Generate Foundry invariant and vulnerability test files")
  .argument("<file>", "Path to Solidity file")
  .option("-o, --output <dir>", "Output directory for test files", "./test")
  .option("-f, --format <type>", "Output format: terminal (default) or md", "terminal")
  .action((file, opts) => {
    run("generate", file, opts);
  });

// ─── full command (analyze + generate) ───
program
  .command("full")
  .description("Full analysis: discover invariants, detect vulnerabilities, and generate tests")
  .argument("<file>", "Path to Solidity file")
  .option("-o, --output <dir>", "Output directory for test files", "./test")
  .option("-f, --format <type>", "Output format: terminal (default) or md", "terminal")
  .action((file, opts) => {
    run("full", file, opts);
  });

function run(mode, file, opts = {}) {
  const filePath = path.resolve(file);
  const format = opts.format || "terminal";

  if (!fs.existsSync(filePath)) {
    console.error(chalk.red(`  Error: File not found: ${filePath}`));
    process.exit(1);
  }

  console.log(chalk.bold.white("\n  sol-shield v0.1.0"));
  console.log(chalk.gray(`  Analyzing: ${filePath}\n`));

  let contracts;
  try {
    contracts = parseFile(filePath);
  } catch (err) {
    console.error(chalk.red(`  Parse error: ${err.message}`));
    process.exit(1);
  }

  if (contracts.length === 0) {
    console.log(chalk.yellow("  No contracts found in file."));
    process.exit(0);
  }

  let totalInvariants = 0;
  let totalVulns = 0;
  let totalGas = 0;
  let allVulns = [];
  let generatedFiles = [];
  let mdReports = [];
  let contractsAnalyzed = 0;

  for (const contract of contracts) {
    if (contract.kind === "interface" || contract.kind === "library") continue;
    contractsAnalyzed++;

    console.log(chalk.bold.white(`  Contract: ${contract.name}`));
    console.log(chalk.gray(`  ${"─".repeat(40)}`));

    // Discover invariants
    const invariants = discoverInvariants(contract);
    totalInvariants += invariants.length;

    if (mode === "analyze" || mode === "full") {
      console.log(formatInvariants(invariants, contract.name));
    }

    // Detect vulnerabilities
    const vulns = detectVulnerabilities(contract);
    totalVulns += vulns.length;
    allVulns.push(...vulns);

    if (mode === "analyze" || mode === "full") {
      console.log(formatVulnerabilities(vulns, contract.name));
    }

    // Detect gas issues
    const gasIssues = detectGasIssues(contract);
    totalGas += gasIssues.length;

    if (mode === "analyze" || mode === "full") {
      console.log(formatGasIssues(gasIssues, contract.name));
    }

    // Generate tests
    if (mode === "generate" || mode === "full") {
      const outputDir = path.resolve(opts.output || "./test");
      const files = generateFoundryTests(contract, invariants, vulns, outputDir);
      generatedFiles.push(...files);
    }

    // Collect data for markdown report
    const scoreData = calculateSecurityScore(vulns);
    if (format === "md") {
      mdReports.push({ contractName: contract.name, invariants, vulns, gasIssues, scoreData });
    }
  }

  // Security Score
  const overallScore = calculateSecurityScore(allVulns);
  console.log(formatSecurityScore(overallScore));

  // Summary
  console.log(chalk.bold.white(`\n  ${"═".repeat(40)}`));
  console.log(chalk.bold.white("  Summary"));
  console.log(chalk.gray(`  ${"─".repeat(40)}`));
  console.log(`  Contracts analyzed: ${chalk.cyan(contractsAnalyzed)}`);
  console.log(`  Invariant properties: ${chalk.cyan(totalInvariants)}`);
  console.log(
    `  Vulnerabilities found: ${totalVulns > 0 ? chalk.red(totalVulns) : chalk.green(totalVulns)}`
  );
  console.log(`  Gas optimizations: ${chalk.magenta(totalGas)}`);

  if (generatedFiles.length > 0) {
    console.log(`\n  ${chalk.green("Generated test files:")}`);
    for (const f of generatedFiles) {
      console.log(`    ${chalk.gray(">")} ${f}`);
    }
  }

  // Markdown report
  if (format === "md") {
    const outputDir = path.resolve(opts.output || ".");
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

    for (const r of mdReports) {
      const md = generateMarkdownReport(r.contractName, r.invariants, r.vulns, r.gasIssues, r.scoreData);
      const mdPath = path.join(outputDir, `${r.contractName}.report.md`);
      fs.writeFileSync(mdPath, md, "utf8");
      console.log(`\n  ${chalk.green("Generated report:")} ${mdPath}`);
    }
  }

  console.log("");
}

program.parse();
