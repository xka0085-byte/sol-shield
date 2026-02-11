const parser = require("@solidity-parser/parser");
const fs = require("fs");
const path = require("path");

/**
 * Parse a Solidity file and extract structured contract information
 */
function parseFile(filePath) {
  const source = fs.readFileSync(path.resolve(filePath), "utf8");
  const ast = parser.parse(source, { loc: true, range: true });
  const contracts = [];

  for (const node of ast.children) {
    if (node.type === "ContractDefinition") {
      contracts.push(extractContract(node, source));
    }
  }
  return contracts;
}

function extractContract(node, source) {
  const contract = {
    name: node.name,
    kind: node.kind, // "contract", "interface", "library"
    baseContracts: (node.baseContracts || []).map((b) => b.baseName.namePath),
    stateVars: [],
    functions: [],
    events: [],
    modifiers: [],
    mappings: [],
  };

  for (const sub of node.subNodes) {
    switch (sub.type) {
      case "StateVariableDeclaration":
        for (const v of sub.variables) {
          const info = extractStateVar(v, sub);
          contract.stateVars.push(info);
          if (v.typeName && v.typeName.type === "Mapping") {
            contract.mappings.push(info);
          }
        }
        break;
      case "FunctionDefinition":
        contract.functions.push(extractFunction(sub, source));
        break;
      case "EventDefinition":
        contract.events.push(extractEvent(sub));
        break;
      case "ModifierDefinition":
        contract.modifiers.push({ name: sub.name });
        break;
    }
  }
  return contract;
}

function extractStateVar(v, decl) {
  return {
    name: v.name,
    typeName: typeToString(v.typeName),
    visibility: v.visibility || "internal",
    isDeclaredConst: v.isDeclaredConst || false,
    isImmutable: v.isImmutable || false,
    isMapping: v.typeName && v.typeName.type === "Mapping",
    mappingKeyType:
      v.typeName && v.typeName.type === "Mapping"
        ? typeToString(v.typeName.keyType)
        : null,
    mappingValueType:
      v.typeName && v.typeName.type === "Mapping"
        ? typeToString(v.typeName.valueType)
        : null,
  };
}

function extractFunction(node, source) {
  const fn = {
    name: node.name || (node.isConstructor ? "constructor" : node.isFallback ? "fallback" : "receive"),
    visibility: node.visibility || "public",
    stateMutability: node.stateMutability || null,
    isConstructor: node.isConstructor || false,
    isFallback: node.isFallback || false,
    isReceiveEther: node.isReceiveEther || false,
    params: (node.parameters || []).map((p) => ({
      name: p.name,
      type: typeToString(p.typeName),
    })),
    returnParams: (node.returnParameters || []).map((p) => ({
      name: p.name,
      type: typeToString(p.typeName),
    })),
    modifiers: (node.modifiers || []).map((m) => m.name),
    requires: [],
    externalCalls: [],
    stateChanges: [],
    loc: node.loc,
  };

  if (node.body) {
    analyzeBody(node.body, fn);
  }
  return fn;
}

function analyzeBody(body, fn) {
  if (!body || !body.statements) return;
  for (const stmt of body.statements) {
    walkStatement(stmt, fn);
  }
}

function walkExprForExternalCalls(expr, stmt, fn) {
  if (!expr) return;
  // Direct: addr.call(...)
  if (expr.type === "FunctionCall" && expr.expression) {
    let memberExpr = expr.expression;
    // Handle NameValueExpression: addr.call{value: x}(...)
    if (memberExpr.type === "NameValueExpression" && memberExpr.expression) {
      memberExpr = memberExpr.expression;
    }
    if (memberExpr.type === "MemberAccess") {
      const member = memberExpr.memberName;
      if (["call", "transfer", "send", "delegatecall", "staticcall"].includes(member)) {
        fn.externalCalls.push({
          type: member,
          loc: stmt.loc,
        });
      }
    }
  }
}

function walkStatement(stmt, fn) {
  if (!stmt) return;

  // Detect require/revert statements
  if (stmt.type === "ExpressionStatement" && stmt.expression) {
    const expr = stmt.expression;
    if (expr.type === "FunctionCall" && expr.expression) {
      const callName =
        expr.expression.name ||
        (expr.expression.memberName) ||
        "";
      if (callName === "require" || callName === "revert") {
        const args = (expr.arguments || []).map(argToString);
        fn.requires.push({ type: callName, args });
      }
      // Detect external calls: addr.call, addr.transfer, addr.send
      let callExpr = expr.expression;
      if (callExpr && callExpr.type === "NameValueExpression" && callExpr.expression) {
        callExpr = callExpr.expression;
      }
      if (callExpr && callExpr.type === "MemberAccess") {
        const member = callExpr.memberName;
        if (["call", "transfer", "send", "delegatecall", "staticcall"].includes(member)) {
          fn.externalCalls.push({
            type: member,
            loc: stmt.loc,
          });
        }
      }
    }
    // Detect state changes (assignments)
    if (expr.type === "BinaryOperation" && ["=", "+=", "-=", "*=", "/="].includes(expr.operator)) {
      fn.stateChanges.push({
        target: argToString(expr.left),
        operator: expr.operator,
        loc: stmt.loc,
      });
    }
  }

  // Detect external calls in variable declarations: (bool success, ) = addr.call{value: x}("")
  if (stmt.type === "VariableDeclarationStatement" && stmt.initialValue) {
    walkExprForExternalCalls(stmt.initialValue, stmt, fn);
  }

  // Recurse into blocks
  if (stmt.type === "Block" && stmt.statements) {
    for (const s of stmt.statements) walkStatement(s, fn);
  }
  if (stmt.type === "IfStatement") {
    walkStatement(stmt.trueBody, fn);
    if (stmt.falseBody) walkStatement(stmt.falseBody, fn);
  }
  if (stmt.type === "ForStatement" || stmt.type === "WhileStatement") {
    walkStatement(stmt.body, fn);
  }
}

function extractEvent(node) {
  return {
    name: node.name,
    params: (node.parameters || []).map((p) => ({
      name: p.name,
      type: typeToString(p.typeName),
      isIndexed: p.isIndexed || false,
    })),
  };
}

function typeToString(typeName) {
  if (!typeName) return "unknown";
  if (typeName.type === "ElementaryTypeName") return typeName.name;
  if (typeName.type === "UserDefinedTypeName") return typeName.namePath;
  if (typeName.type === "Mapping")
    return `mapping(${typeToString(typeName.keyType)} => ${typeToString(typeName.valueType)})`;
  if (typeName.type === "ArrayTypeName")
    return `${typeToString(typeName.baseTypeName)}[]`;
  return "unknown";
}

function argToString(arg) {
  if (!arg) return "";
  if (arg.type === "Identifier") return arg.name;
  if (arg.type === "StringLiteral") return `"${arg.value}"`;
  if (arg.type === "NumberLiteral") return arg.number;
  if (arg.type === "BooleanLiteral") return String(arg.value);
  if (arg.type === "MemberAccess")
    return `${argToString(arg.expression)}.${arg.memberName}`;
  if (arg.type === "IndexAccess")
    return `${argToString(arg.base)}[${argToString(arg.index)}]`;
  if (arg.type === "BinaryOperation")
    return `${argToString(arg.left)} ${arg.operator} ${argToString(arg.right)}`;
  if (arg.type === "FunctionCall")
    return `${argToString(arg.expression)}(${(arg.arguments || []).map(argToString).join(", ")})`;
  return "";
}

module.exports = { parseFile };
