# Controlling Decompiler Optimizations in Ghidra

## The Problem

When analyzing malware, the Ghidra decompiler automatically optimizes away redundant control flow patterns, including:
- Redundant conditional branches with the same condition
- Complementary conditionals (e.g., `if (x)` followed by `if (!x)`)
- Obfuscated control flow patterns
- Anti-analysis checks

This happens through the **`ActionConditionalExe`** optimization pass, which uses `BooleanExpressionMatch` to detect and remove these patterns.

## Can You Disable Block Removal?

**No.** There is no way to selectively disable the `ActionConditionalExe` pass.

### Why Not?

From `coreaction.cc` (lines 5420-5444), the `conditionalexe` action is included in ALL simplification styles:

```cpp
// "decompile" group - line 5426
const char *decompmemb[] = { ..., "conditionalexe", "" };

// "normalize" group - line 5437
const char *normali[] = { ..., "conditionalexe", "" };

// "paramid" group - line 5444
const char *paramid[] = { ..., "conditionalexe", "" };
```

**Conclusion**: Switching simplification styles won't help - they all run this optimization.

## Available Options

### Option 1: Use Raw P-code (RECOMMENDED for Malware Analysis)

Access P-code directly from instructions before any decompiler optimizations:

```java
Listing listing = program.getListing();
InstructionIterator instIter = listing.getInstructions(function.getBody(), true);

while (instIter.hasNext()) {
    Instruction instr = instIter.next();
    PcodeOp[] rawPcode = instr.getPcode();  // Unoptimized!

    for (PcodeOp op : rawPcode) {
        // Analyze raw P-code
        if (op.getOpcode() == PcodeOp.CBRANCH) {
            // Every branch visible, nothing removed
        }
    }
}
```

**Pros:**
✅ Complete control flow preserved
✅ All obfuscation patterns visible
✅ Redundant conditionals not removed
✅ Anti-analysis techniques detectable
✅ Perfect for signature generation

**Cons:**
❌ No cross-instruction data flow
❌ No SSA form
❌ No type propagation
❌ More verbose
❌ You must build your own CFG

**Best for:**
- Initial malware triage
- Obfuscation detection
- Packer/protector identification
- IoC extraction
- Signature development

### Option 2: Disable "Predicate Simplification" (LIMITED HELP)

```java
DecompInterface decompiler = new DecompInterface();
DecompileOptions options = new DecompileOptions();

options.setSimplifyPredication(false);  // Default: true

decompiler.setOptions(options);
decompiler.openProgram(program);
```

**What this controls:**
- Affects `RuleConditionalMove` and `RuleOrPredicate`
- From DecompileOptions.java:49-53: *"multiple conditionally executed instructions depending on one predicate will be combined"*
- **NOT** the same as block removal from redundant conditionals

**Why it probably won't help:**
- This is for predicated instruction sets (ARM conditional execution, Intel Itanium)
- Does NOT control the `ActionConditionalExe` pass that removes blocks
- Unlikely to affect typical x86/x64 malware

### Option 3: Hybrid Approach - Compare Both

The most effective malware analysis strategy:

```java
// 1. Analyze raw P-code
Map<Address, RawBlock> rawCFG = buildRawCFG(program, function);
int rawBranchCount = countConditionalBranches(rawCFG);

// 2. Analyze decompiled P-code
DecompileResults results = decompileFunction(function);
HighFunction hf = results.getHighFunction();
int optimizedBranchCount = countOptimizedBranches(hf);

// 3. What was removed?
int removed = rawBranchCount - optimizedBranchCount;

if (removed > 3) {
    System.out.println("SUSPICIOUS: " + removed +
                      " redundant conditionals removed");
    System.out.println("Possible anti-analysis obfuscation");
}
```

**This tells you:**
- What obfuscation techniques were used
- Which patterns the decompiler recognized
- Family-specific signatures (even after cleanup)
- Control flow complexity metrics

## Practical Malware Analysis Workflow

### Stage 1: Raw P-code Analysis (Obfuscation Detection)

```java
// Build complete, unoptimized CFG
Map<Address, RawBasicBlock> rawCFG = buildRawCFG(program, function);

// Find ALL conditional branches
List<ConditionalBranch> branches = findAllBranches(rawCFG);

// Detect patterns
for (int i = 0; i < branches.size(); i++) {
    for (int j = i + 1; j < branches.size(); j++) {
        if (sameCondition(branches[i], branches[j])) {
            // Redundant check - obfuscation or anti-debug
        }
        if (complementaryConditions(branches[i], branches[j])) {
            // VM/debugger check pattern
        }
    }
}
```

**Detects:**
- Opaque predicates
- Redundant VM checks
- Anti-debugging patterns
- Packer signatures
- Control flow flattening

### Stage 2: Decompiled Analysis (Behavioral Understanding)

```java
// Get cleaned-up, understandable code
DecompileResults results = decompileFunction(function);
HighFunction hf = results.getHighFunction();

// Understand what the malware actually does
// (easier after optimizations remove noise)
```

**Provides:**
- Clear behavioral analysis
- API usage patterns
- Data flow understanding
- Crypto algorithm identification

### Stage 3: Differential Analysis (Signature Generation)

```java
// Compare what changed
AnalysisReport report = compareRawVsOptimized(function);

System.out.println(report);
// Output:
// Raw blocks: 47
// Optimized blocks: 12
// Blocks removed: 35 ⚠️ SUSPICIOUS
//
// Patterns detected:
// - 8 redundant IsDebuggerPresent() checks
// - 4 complementary VM detection conditionals
// - Possible packer: UPX v3.x signature
```

## Other Decompiler Options

While you can't disable block removal, other options may help:

```java
DecompileOptions options = new DecompileOptions();

// Analysis options
options.setEliminateUnreachable(true);        // Keep dead code?
options.setSimplifyDoublePrecision(true);     // Extended int ops
options.setIgnoreUnimplemented(false);        // Treat unimpl as NOP?
options.setInferConstantPointers(true);       // Const -> pointer inference

// These won't stop block removal, but may preserve other patterns
```

## What Gets Optimized Away?

### Example 1: Redundant Checks

**Before (Raw P-code):**
```
Block 1: if (IsDebuggerPresent()) goto exit
Block 2: normal_execution()
Block 3: if (IsDebuggerPresent()) goto exit  // REDUNDANT
Block 4: more_execution()
```

**After (Decompiled):**
```
Block 1: if (IsDebuggerPresent()) goto exit
Block 2: normal_execution()
Block 3: more_execution()
```

**What you miss:** The intentional redundancy (anti-analysis indicator)

### Example 2: Complementary Conditions

**Before (Raw P-code):**
```
Block 1: if (in_vm) goto benign_behavior
Block 2: malicious_code()
Block 3: if (!in_vm) goto more_malicious  // COMPLEMENTARY
Block 4: benign_decoy()
```

**After (Decompiled):**
```
Block 1: if (in_vm)
           benign_behavior()
         else
           malicious_code()
           more_malicious()
```

**What you miss:** The specific VM detection pattern (malware family signature)

### Example 3: Opaque Predicates

**Before (Raw P-code):**
```
Block 1: if ((x*x) >= 0) goto always_taken  // Always true
Block 2: unreachable_code()
Block 3: always_taken: real_code()
```

**After (Decompiled):**
```
Block 1: real_code()
```

**What you miss:** The obfuscation technique itself

## Summary

| Approach | Control Flow | Data Flow | Obfuscation | Use Case |
|----------|--------------|-----------|-------------|----------|
| **Raw P-code** | ✅ Complete | ❌ Limited | ✅ Visible | Obfuscation detection |
| **Decompiled** | ⚠️ Simplified | ✅ Full SSA | ❌ Hidden | Behavioral analysis |
| **Both (Hybrid)** | ✅ Complete | ✅ Full SSA | ✅ Visible | Professional malware analysis |

## Recommendation for Malware Analysis

**Use the hybrid approach:**

1. **Raw P-code** → Detect obfuscation, anti-analysis, packer signatures
2. **Decompiled** → Understand behavior, identify crypto, API patterns
3. **Compare** → Generate robust signatures, identify malware families

See `MalwareAnalysisRawPcodeExample.java` for a complete implementation.

## References

- **C++ Code**: `Ghidra/Features/Decompiler/src/decompile/cpp/`
  - `condexe.cc` - ConditionalExecution optimization (lines 80-503)
  - `expression.cc` - BooleanExpressionMatch (lines 220-232)
  - `coreaction.cc` - Action groups (lines 5420-5444)

- **Java API**: `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/`
  - `DecompInterface.java` - Main decompiler interface
  - `DecompileOptions.java` - Available options
  - `DecompileResults.java` - Accessing results

- **P-code API**: `ghidra.program.model.pcode.*`
  - `PcodeOp` - Individual operations
  - `PcodeBlockBasic` - Optimized basic blocks
  - `HighFunction` - Decompiled function representation
