# Conditional Branch Analysis in Ghidra - Java API Approach

## Overview

This document explains how to analyze and compare conditional branches in Ghidra using the Java API, implementing functionality similar to the internal C++ `BooleanExpressionMatch` class.

## Background

The C++ decompiler engine has internal classes for comparing conditional branches:
- **`BooleanMatch`** (expression.cc) - Compares two boolean expressions
- **`BooleanExpressionMatch`** (expression.cc) - Compares CBRANCH operations
- **`ConditionalExecution`** (condexe.cc) - Uses these to optimize control flow

These are **NOT** exposed to Java. Instead, we work with the decompiler's output.

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│  Your Java Application                          │
├─────────────────────────────────────────────────┤
│  DecompInterface                                │
│  ├─> Communicates with C++ decompiler process  │
│  └─> Returns DecompileResults                  │
├─────────────────────────────────────────────────┤
│  DecompileResults                               │
│  ├─> HighFunction (high-level representation)  │
│  ├─> BlockGraph (basic block structure)        │
│  └─> PcodeOpAST (individual operations)        │
└─────────────────────────────────────────────────┘
```

## Key Classes

### 1. DecompInterface
Entry point for decompilation. Manages the C++ decompiler process.

```java
DecompInterface decompiler = new DecompInterface();
decompiler.openProgram(program);
DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
```

### 2. DecompileResults
Contains the decompilation output:
- `getHighFunction()` - Returns the high-level function representation
- `getCCodeMarkup()` - Returns marked-up C code
- `decompileCompleted()` - Check if successful

### 3. HighFunction
The high-level function abstraction:
- `getBasicBlocks()` - Returns ArrayList<PcodeBlockBasic>
- `getLocalSymbolMap()` - Variable mappings
- Inherits from `PcodeSyntaxTree`

### 4. PcodeBlockBasic
Represents a basic block:
- `getIterator()` - Iterate through PcodeOps
- `getFirstOp()` / `getLastOp()` - Get block endpoints
- `getInSize()` / `getOutSize()` - Number of incoming/outgoing edges

### 5. PcodeOp
Individual operation:
- `getOpcode()` - Returns operation type (CBRANCH, INT_EQUAL, etc.)
- `getInput(i)` - Get input Varnode
- `getOutput()` - Get output Varnode
- `isBooleanFlip()` - Check if branch condition is negated

### 6. Varnode
Represents a value:
- `getDef()` - Get the PcodeOp that defines this value
- `isConstant()` - Check if constant
- `getOffset()` - Get constant value

## Approach: Analyzing Decompiler Output

### Step 1: Decompile the Function

```java
DecompInterface decompiler = new DecompInterface();
decompiler.openProgram(program);
DecompileResults results = decompiler.decompileFunction(function, 30, monitor);

HighFunction highFunction = results.getHighFunction();
```

### Step 2: Find All Conditional Branches

```java
ArrayList<PcodeBlockBasic> basicBlocks = highFunction.getBasicBlocks();

for (PcodeBlockBasic block : basicBlocks) {
    PcodeOp lastOp = block.getLastOp();

    if (lastOp != null && lastOp.getOpcode() == PcodeOp.CBRANCH) {
        // This is a conditional branch
        Varnode condition = lastOp.getInput(1);  // Input 1 is the boolean condition
        // Analyze the condition...
    }
}
```

### Step 3: Analyze Boolean Conditions

For each CBRANCH, trace back through the boolean expression:

```java
Varnode booleanCondition = cbranchOp.getInput(1);
PcodeOp definingOp = booleanCondition.getDef();

if (definingOp != null) {
    switch (definingOp.getOpcode()) {
        case PcodeOp.INT_EQUAL:
            // Comparison: var == value
            break;
        case PcodeOp.INT_LESS:
            // Comparison: var < value
            break;
        case PcodeOp.BOOL_AND:
            // Boolean combination: cond1 && cond2
            Varnode left = definingOp.getInput(0);
            Varnode right = definingOp.getInput(1);
            // Recursively analyze...
            break;
        case PcodeOp.BOOL_NEGATE:
            // Negation: !cond
            break;
    }
}
```

### Step 4: Compare Two Conditions

To determine if two conditions are the same, complementary, or unrelated:

1. **Direct comparison**: Are they the exact same Varnode?
2. **Constant comparison**: Are they constants with the same/opposite values?
3. **Operation comparison**: Do they use the same/complementary operations?
4. **Recursive comparison**: For compound expressions (AND, OR, XOR)

## Comparison Algorithm

The algorithm mirrors the C++ `BooleanMatch::evaluate()` logic:

```java
ComparisonResult compareConditions(Varnode vn1, Varnode vn2, int maxDepth) {
    // 1. Check identity
    if (vn1 == vn2) return SAME;

    // 2. Check for negation (flips result)
    if (vn1.getDef().getOpcode() == BOOL_NEGATE) {
        result = compareConditions(vn1.getDef().getInput(0), vn2, maxDepth);
        return flip(result);  // SAME <-> COMPLEMENTARY
    }

    // 3. Check if both are boolean operations
    PcodeOp op1 = vn1.getDef();
    PcodeOp op2 = vn2.getDef();

    // 4. Compare operations
    if (op1.getOpcode() == op2.getOpcode()) {
        if (sameInputs(op1, op2)) return SAME;
        if (complementaryInputs(op1, op2)) return COMPLEMENTARY;
    }

    // 5. Check for complementary operations (e.g., == vs !=)
    if (isComplementaryOp(op1, op2)) {
        if (sameInputs(op1, op2)) return COMPLEMENTARY;
    }

    return UNCORRELATED;
}
```

## Example Use Cases

### Use Case 1: Detect Redundant Conditionals

```java
// Find if two branches test the same condition
if (compareBranches(branch1, branch2) == ComparisonResult.SAME) {
    System.out.println("Redundant conditional detected!");
}
```

### Use Case 2: Identify Complementary Branches

```java
// Find if-else patterns
if (compareBranches(branch1, branch2) == ComparisonResult.COMPLEMENTARY) {
    System.out.println("Complementary branches (if-else pattern)");
}
```

### Use Case 3: Control Flow Simplification

```java
// Detect patterns like:
//   if (condition) { ... }
//   if (condition) { ... }  // Same condition tested twice

for (int i = 0; i < branches.size(); i++) {
    for (int j = i + 1; j < branches.size(); j++) {
        if (compareBranches(branches[i], branches[j]) == ComparisonResult.SAME) {
            // Potential optimization opportunity
        }
    }
}
```

## Important Considerations

### 1. Depth Limiting
Like the C++ version, limit recursion depth to avoid expensive analysis:
```java
private static final int MAX_DEPTH = 1;  // Match C++ implementation
```

### 2. Boolean Flip Flag
The CBRANCH operation has a `isBooleanFlip()` flag that inverts the condition:
```java
boolean flip = cbranchOp.isBooleanFlip();
if (flip) {
    result = flipResult(result);
}
```

### 3. Commutative Operations
Handle commutative operations (AND, OR, XOR) by trying both orderings:
```java
// Try: op1.in[0] vs op2.in[0] and op1.in[1] vs op2.in[1]
// If that fails, try: op1.in[0] vs op2.in[1] and op1.in[1] vs op2.in[0]
```

### 4. Special Cases

**De Morgan's Law**: `!(A && B) == !A || !B`
```java
if (op1 == BOOL_AND && op2 == BOOL_OR) {
    if (both inputs are complementary) {
        return COMPLEMENTARY;
    }
}
```

**Adjacent Constants**: `x < 9` and `8 < x` are complementary
```java
if (val1 + 1 == val2 && slots are swapped) {
    return COMPLEMENTARY;
}
```

## Limitations

1. **No Access to Internal Optimizations**: The C++ decompiler performs many optimizations before we see the results.

2. **Simplified Analysis**: Some complex boolean expressions may not be fully analyzed.

3. **Performance**: Analyzing in Java is slower than the C++ implementation.

4. **Limited Context**: We don't have access to heritage information, dominator trees, etc. that the C++ code uses.

## Performance Tips

1. **Cache Results**: If comparing many branches, cache comparison results
2. **Limit Scope**: Only analyze blocks of interest
3. **Use Block Graph**: Leverage the control flow graph to focus on related blocks
4. **Dispose Decompiler**: Always dispose of DecompInterface when done

```java
try {
    decompiler.openProgram(program);
    // ... do work ...
} finally {
    decompiler.dispose();
}
```

## Complete Working Example

See `ConditionalBranchComparer.java` for a full implementation with:
- Finding all conditional branches in a function
- Comparing branch conditions
- Handling negation, boolean combinations, and complementary operations
- Example usage

## References

- **C++ Implementation**: `Ghidra/Features/Decompiler/src/decompile/cpp/expression.cc`
  - `BooleanMatch::evaluate()` (lines 111-216)
  - `BooleanExpressionMatch::verifyCondition()` (lines 220-232)

- **C++ Control Flow**: `Ghidra/Features/Decompiler/src/decompile/cpp/condexe.cc`
  - `ConditionalExecution::verifySameCondition()` (lines 80-94)

- **Java API Documentation**: See Ghidra's JavaDoc for:
  - `ghidra.app.decompiler.DecompInterface`
  - `ghidra.program.model.pcode.HighFunction`
  - `ghidra.program.model.pcode.PcodeOp`
  - `ghidra.program.model.pcode.Varnode`
