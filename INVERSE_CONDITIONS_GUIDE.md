# Guide: Identifying Inverse Conditions in Ghidra CBRANCH Operations

## Overview

When analyzing conditional branches (CBRANCH) in Ghidra's Pcode, you may need to determine if two branches have **inverse** (opposite) conditions. This is critical for:
- Control flow analysis
- Detecting if-else patterns
- Understanding complementary branch logic
- Decompilation and optimization

## CBRANCH Structure

A CBRANCH operation has this format:
```
CBRANCH <destination>, <condition>
```

- **Input[0]**: Branch destination address
- **Input[1]**: Condition varnode (boolean value)

The branch is **taken if the condition is TRUE**.

## Algorithm to Detect Inverse Conditions

### Step 1: Extract the Condition Operations

```java
// For each CBRANCH, get the condition varnode
Varnode cond1Varnode = cbranch1.getInput(1);
Varnode cond2Varnode = cbranch2.getInput(1);

// Get the PcodeOp that DEFINES each condition
PcodeOp cond1Op = cond1Varnode.getDef();
PcodeOp cond2Op = cond2Varnode.getDef();
```

The condition varnode is typically produced by a comparison operation like:
- `INT_EQUAL` (==)
- `INT_NOTEQUAL` (!=)
- `INT_SLESS` (<)
- `INT_SLESSEQUAL` (<=)
- etc.

### Step 2: Get OpCode Representations

```java
OpCode opCode1 = OpCode.getOpcode(cond1Op.getOpcode());
OpCode opCode2 = OpCode.getOpcode(cond2Op.getOpcode());
```

### Step 3: Check for Inverse Using getOpCodeFlip()

```java
OpCode invertedOp1 = opCode1.getOpCodeFlip();
boolean areInverse = (invertedOp1 == opCode2);
```

**Key method:** `OpCode.getOpCodeFlip()`

This returns the inverse operation:
- `INT_EQUAL` ↔ `INT_NOTEQUAL`
- `INT_SLESS` ↔ `INT_SLESSEQUAL`
- `INT_LESS` ↔ `INT_LESSEQUAL`
- `FLOAT_EQUAL` ↔ `FLOAT_NOTEQUAL`
- `BOOL_NEGATE` ↔ `COPY`

If it returns `CPUI_MAX`, the operation has no inverse.

### Step 4: Check if Operand Swap is Required

Some inverse conditions require **swapped operands**:

```java
boolean needsSwap = opCode1.getBooleanFlip();
```

**Key method:** `OpCode.getBooleanFlip()`

Returns `true` for operations that need parameter reordering:
- `INT_SLESS` → true (a < b becomes b >= a)
- `INT_SLESSEQUAL` → true (a <= b becomes b > a)
- `INT_LESS` → true (unsigned)
- `INT_LESSEQUAL` → true (unsigned)
- `FLOAT_LESS` → true
- `FLOAT_LESSEQUAL` → true

Returns `false` for symmetric operations:
- `INT_EQUAL` → false (a == b is same as b == a)
- `INT_NOTEQUAL` → false
- `BOOL_NEGATE` → false

### Step 5: Verify Operand Relationship

If `needsSwap` is true, verify operands are actually swapped:

```java
Varnode op1Left = cond1Op.getInput(0);
Varnode op1Right = cond1Op.getInput(1);
Varnode op2Left = cond2Op.getInput(0);
Varnode op2Right = cond2Op.getInput(1);

if (needsSwap) {
    // Operands should be reversed
    boolean isValid = (op1Left.equals(op2Right) && op1Right.equals(op2Left));
} else {
    // Operands should be the same
    boolean isValid = (op1Left.equals(op2Left) && op1Right.equals(op2Right));
}
```

## Complete Example

### Example 1: Simple Inverse (No Swap)

**CBRANCH 1:**
```
condition: INT_EQUAL $r0, 0x5
CBRANCH 0x1000, condition    // if (r0 == 5) goto 0x1000
```

**CBRANCH 2:**
```
condition: INT_NOTEQUAL $r0, 0x5
CBRANCH 0x2000, condition    // if (r0 != 5) goto 0x2000
```

**Analysis:**
1. OpCode1 = `INT_EQUAL`, OpCode2 = `INT_NOTEQUAL`
2. `INT_EQUAL.getOpCodeFlip()` = `INT_NOTEQUAL` ✓
3. `INT_EQUAL.getBooleanFlip()` = `false` (no swap needed)
4. Operands: both use `($r0, 0x5)` ✓

**Result:** ✓ INVERSE (same operands)

### Example 2: Inverse with Operand Swap

**CBRANCH 1:**
```
condition: INT_SLESS $r0, $r1        // r0 < r1
CBRANCH 0x1000, condition            // if (r0 < r1) goto 0x1000
```

**CBRANCH 2:**
```
condition: INT_SLESSEQUAL $r1, $r0   // r1 <= r0  (equivalent to r0 >= r1)
CBRANCH 0x2000, condition            // if (r1 <= r0) goto 0x2000
```

**Analysis:**
1. OpCode1 = `INT_SLESS`, OpCode2 = `INT_SLESSEQUAL`
2. `INT_SLESS.getOpCodeFlip()` = `INT_SLESSEQUAL` ✓
3. `INT_SLESS.getBooleanFlip()` = `true` (swap required)
4. Operands: op1 uses `($r0, $r1)`, op2 uses `($r1, $r0)` - SWAPPED ✓

**Result:** ✓ INVERSE (swapped operands)

**Logical verification:**
- `r0 < r1` is the inverse of `r0 >= r1`
- `r0 >= r1` is equivalent to `r1 <= r0`

### Example 3: Boolean Negation

**CBRANCH 1:**
```
condition: BOOL_NEGATE $r0           // !r0
CBRANCH 0x1000, condition            // if (!r0) goto 0x1000
```

**CBRANCH 2:**
```
condition: COPY $r0                  // r0
CBRANCH 0x2000, condition            // if (r0) goto 0x2000
```

**Analysis:**
1. OpCode1 = `BOOL_NEGATE`, OpCode2 = `COPY`
2. `BOOL_NEGATE.getOpCodeFlip()` = `COPY` ✓
3. `BOOL_NEGATE.getBooleanFlip()` = `false`

**Result:** ✓ INVERSE

## Inverse Condition Reference Table

| Condition Type | OpCode | Inverse OpCode | Swap Required | Example |
|----------------|--------|----------------|---------------|---------|
| Equal | INT_EQUAL | INT_NOTEQUAL | No | (a == b) ↔ (a != b) |
| Not Equal | INT_NOTEQUAL | INT_EQUAL | No | (a != b) ↔ (a == b) |
| Signed Less | INT_SLESS | INT_SLESSEQUAL | **Yes** | (a < b) ↔ (b >= a) |
| Signed Less/Equal | INT_SLESSEQUAL | INT_SLESS | **Yes** | (a <= b) ↔ (b > a) |
| Unsigned Less | INT_LESS | INT_LESSEQUAL | **Yes** | (a < b) ↔ (b >= a) |
| Unsigned Less/Equal | INT_LESSEQUAL | INT_LESS | **Yes** | (a <= b) ↔ (b > a) |
| Boolean Negate | BOOL_NEGATE | COPY | No | (!x) ↔ (x) |
| Float Equal | FLOAT_EQUAL | FLOAT_NOTEQUAL | No | (a == b) ↔ (a != b) |
| Float Not Equal | FLOAT_NOTEQUAL | FLOAT_EQUAL | No | (a != b) ↔ (a == b) |
| Float Less | FLOAT_LESS | FLOAT_LESSEQUAL | **Yes** | (a < b) ↔ (b >= a) |
| Float Less/Equal | FLOAT_LESSEQUAL | FLOAT_LESS | **Yes** | (a <= b) ↔ (b > a) |

## Key Ghidra Classes and Methods

### OpCode Enum
Location: `ghidra/pcodeCPort/opcodes/OpCode.java`

**Methods:**
- `getOpCodeFlip()`: Returns the inverse OpCode
- `getBooleanFlip()`: Returns true if operands must be swapped
- `getOpcode(int)`: Get OpCode from integer opcode value
- `getName()`: Get string name of operation

### PcodeOp Class
Location: `ghidra/program/model/pcode/PcodeOp.java`

**Methods:**
- `getOpcode()`: Get the integer opcode
- `getInput(int)`: Get input varnode by index
- `getMnemonic()`: Get string representation

**Constants:**
- `PcodeOp.CBRANCH = 5`
- `PcodeOp.INT_EQUAL = 11`
- `PcodeOp.INT_NOTEQUAL = 12`
- etc.

### Varnode Class
Location: `ghidra/program/model/pcode/Varnode.java`

**Methods:**
- `getDef()`: Get the PcodeOp that defines this varnode
- `equals(Object)`: Compare two varnodes

## Common Use Cases

### 1. Finding If-Else Patterns
```
if (a < b) {        // CBRANCH with INT_SLESS
    // block1
} else {
    // block2          // Inverse: CBRANCH with INT_SLESSEQUAL, swapped operands
}
```

### 2. Short-Circuit Evaluation
```
if (a != 0 && b != 0) {
    // CBRANCH with INT_NOTEQUAL on a
    // CBRANCH with INT_NOTEQUAL on b
}
// Inverse path: (a == 0 || b == 0)
```

### 3. Loop Conditions
```
while (i < n) {     // CBRANCH with INT_SLESS
    // loop body
}
// Exit when: i >= n (inverse: INT_SLESSEQUAL with swapped operands)
```

## Implementation Notes

1. **Always check for null**: `varnode.getDef()` can return null if the varnode is an input or constant
2. **Check CPUI_MAX**: `getOpCodeFlip()` returns `OpCode.CPUI_MAX` if there's no inverse
3. **Operand comparison**: Use `Varnode.equals()` for proper comparison
4. **Context matters**: Two conditions being inverses doesn't mean they're part of the same if-else; verify control flow

## References

- **OpCode.java**: Core inverse logic with `getOpCodeFlip()` and `getBooleanFlip()`
- **PcodeOp.java**: Operation definitions and constants
- **SymbolicPropogator.java**: Example of condition evaluation in practice
- **BlockGraph classes**: Control flow structure representation
