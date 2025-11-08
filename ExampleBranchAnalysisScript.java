// Example Ghidra script demonstrating conditional branch analysis
// @category Analysis
// @author Your Name

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.*;

import java.util.*;

public class ExampleBranchAnalysisScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get the current function or analyze all functions
        Function currentFunction = getFunctionContaining(currentAddress);

        if (currentFunction != null) {
            analyzeFunctionBranches(currentFunction);
        } else {
            println("Analyzing all functions...");
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                analyzeFunctionBranches(func);
                count++;
            }
            println("Analyzed " + count + " functions");
        }
    }

    /**
     * Analyze conditional branches in a single function
     */
    private void analyzeFunctionBranches(Function function) throws Exception {
        println("\n=== Analyzing function: " + function.getName() + " ===");

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            decompiler.setSimplificationStyle("decompile");

            // Decompile the function
            DecompileResults results = decompiler.decompileFunction(function, 30, monitor);

            if (!results.decompileCompleted()) {
                println("  Decompilation failed: " + results.getErrorMessage());
                return;
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                println("  No high function available");
                return;
            }

            // Find all conditional branches
            List<BranchInfo> branches = findBranches(highFunction);
            println("  Found " + branches.size() + " conditional branches");

            if (branches.isEmpty()) {
                return;
            }

            // Analyze each branch
            for (BranchInfo branch : branches) {
                println("\n  Branch at " + branch.cbranchOp.getSeqnum().getTarget() + ":");
                describeBranch(branch);
            }

            // Compare pairs of branches
            println("\n  Comparing branch pairs:");
            int sameCount = 0;
            int complementaryCount = 0;

            for (int i = 0; i < branches.size(); i++) {
                for (int j = i + 1; j < branches.size(); j++) {
                    BranchInfo b1 = branches.get(i);
                    BranchInfo b2 = branches.get(j);

                    ComparisonResult result = compareBranches(b1, b2);

                    if (result == ComparisonResult.SAME) {
                        println("    SAME: " + b1.cbranchOp.getSeqnum().getTarget() +
                               " and " + b2.cbranchOp.getSeqnum().getTarget());
                        sameCount++;
                    } else if (result == ComparisonResult.COMPLEMENTARY) {
                        println("    COMPLEMENTARY: " + b1.cbranchOp.getSeqnum().getTarget() +
                               " and " + b2.cbranchOp.getSeqnum().getTarget());
                        complementaryCount++;
                    }
                }
            }

            if (sameCount > 0) {
                println("\n  Found " + sameCount + " pairs with SAME conditions (potential redundancy)");
            }
            if (complementaryCount > 0) {
                println("  Found " + complementaryCount + " pairs with COMPLEMENTARY conditions");
            }

        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Find all conditional branches in the function
     */
    private List<BranchInfo> findBranches(HighFunction highFunction) {
        List<BranchInfo> branches = new ArrayList<>();
        ArrayList<PcodeBlockBasic> basicBlocks = highFunction.getBasicBlocks();

        for (PcodeBlockBasic block : basicBlocks) {
            PcodeOp lastOp = block.getLastOp();

            if (lastOp != null && lastOp.getOpcode() == PcodeOp.CBRANCH) {
                branches.add(new BranchInfo(block, lastOp));
            }
        }

        return branches;
    }

    /**
     * Describe a branch condition in human-readable form
     */
    private void describeBranch(BranchInfo branch) {
        Varnode condition = branch.booleanCondition;
        PcodeOp defOp = condition.getDef();

        if (defOp == null) {
            println("    Condition: " + condition);
            return;
        }

        String opName = getOpName(defOp.getOpcode());
        println("    Condition operation: " + opName);

        if (branch.cbranchOp.isBooleanFlip()) {
            println("    (Boolean flip enabled - condition is inverted)");
        }

        // Show inputs for comparison operations
        if (isComparisonOp(defOp.getOpcode())) {
            Varnode input0 = defOp.getInput(0);
            Varnode input1 = defOp.getInput(1);
            println("    Input 0: " + describeVarnode(input0));
            println("    Input 1: " + describeVarnode(input1));
        }
    }

    /**
     * Describe a Varnode
     */
    private String describeVarnode(Varnode vn) {
        if (vn.isConstant()) {
            return "constant 0x" + Long.toHexString(vn.getOffset());
        } else if (vn.isRegister()) {
            return "register " + vn.getAddress();
        } else if (vn.getDef() != null) {
            return getOpName(vn.getDef().getOpcode()) + " result";
        }
        return vn.toString();
    }

    /**
     * Get human-readable operation name
     */
    private String getOpName(int opcode) {
        switch (opcode) {
            case PcodeOp.INT_EQUAL: return "INT_EQUAL (==)";
            case PcodeOp.INT_NOTEQUAL: return "INT_NOTEQUAL (!=)";
            case PcodeOp.INT_LESS: return "INT_LESS (<)";
            case PcodeOp.INT_LESSEQUAL: return "INT_LESSEQUAL (<=)";
            case PcodeOp.INT_SLESS: return "INT_SLESS (signed <)";
            case PcodeOp.INT_SLESSEQUAL: return "INT_SLESSEQUAL (signed <=)";
            case PcodeOp.BOOL_AND: return "BOOL_AND (&&)";
            case PcodeOp.BOOL_OR: return "BOOL_OR (||)";
            case PcodeOp.BOOL_XOR: return "BOOL_XOR (^)";
            case PcodeOp.BOOL_NEGATE: return "BOOL_NEGATE (!)";
            default: return "OPCODE_" + opcode;
        }
    }

    /**
     * Check if operation is a comparison
     */
    private boolean isComparisonOp(int opcode) {
        return opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.INT_NOTEQUAL ||
               opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_LESSEQUAL ||
               opcode == PcodeOp.INT_SLESS || opcode == PcodeOp.INT_SLESSEQUAL;
    }

    // ===== Comparison Logic (simplified version) =====

    enum ComparisonResult { SAME, COMPLEMENTARY, UNCORRELATED }

    class BranchInfo {
        PcodeBlockBasic block;
        PcodeOp cbranchOp;
        Varnode booleanCondition;

        BranchInfo(PcodeBlockBasic block, PcodeOp cbranchOp) {
            this.block = block;
            this.cbranchOp = cbranchOp;
            this.booleanCondition = cbranchOp.getInput(1);
        }
    }

    private ComparisonResult compareBranches(BranchInfo b1, BranchInfo b2) {
        ComparisonResult result = compareConditions(b1.booleanCondition, b2.booleanCondition, 1);

        // Account for boolean flip
        boolean flip1 = b1.cbranchOp.isBooleanFlip();
        boolean flip2 = b2.cbranchOp.isBooleanFlip();

        if (flip1 != flip2) {
            result = flipResult(result);
        }

        return result;
    }

    private ComparisonResult compareConditions(Varnode vn1, Varnode vn2, int maxDepth) {
        if (vn1 == vn2) {
            return ComparisonResult.SAME;
        }

        if (maxDepth <= 0) {
            return ComparisonResult.UNCORRELATED;
        }

        PcodeOp def1 = vn1.getDef();
        PcodeOp def2 = vn2.getDef();

        if (def1 == null || def2 == null) {
            return ComparisonResult.UNCORRELATED;
        }

        // Handle BOOL_NEGATE
        if (def1.getOpcode() == PcodeOp.BOOL_NEGATE) {
            ComparisonResult result = compareConditions(def1.getInput(0), vn2, maxDepth);
            return flipResult(result);
        }
        if (def2.getOpcode() == PcodeOp.BOOL_NEGATE) {
            ComparisonResult result = compareConditions(vn1, def2.getInput(0), maxDepth);
            return flipResult(result);
        }

        int opc1 = def1.getOpcode();
        int opc2 = def2.getOpcode();

        // Same operation with same inputs?
        if (opc1 == opc2 && sameInputs(def1, def2)) {
            return ComparisonResult.SAME;
        }

        // Complementary operations?
        if (isComplementaryOp(opc1, opc2) && sameInputs(def1, def2)) {
            return ComparisonResult.COMPLEMENTARY;
        }

        return ComparisonResult.UNCORRELATED;
    }

    private boolean sameInputs(PcodeOp op1, PcodeOp op2) {
        int numInputs = op1.getNumInputs();
        if (numInputs != op2.getNumInputs()) {
            return false;
        }

        for (int i = 0; i < numInputs; i++) {
            if (!varnodeSame(op1.getInput(i), op2.getInput(i))) {
                return false;
            }
        }

        return true;
    }

    private boolean varnodeSame(Varnode vn1, Varnode vn2) {
        if (vn1 == vn2) return true;
        if (vn1.isConstant() && vn2.isConstant()) {
            return vn1.getOffset() == vn2.getOffset();
        }
        return false;
    }

    private boolean isComplementaryOp(int opc1, int opc2) {
        if (opc1 == PcodeOp.INT_EQUAL && opc2 == PcodeOp.INT_NOTEQUAL) return true;
        if (opc1 == PcodeOp.INT_NOTEQUAL && opc2 == PcodeOp.INT_EQUAL) return true;
        return false;
    }

    private ComparisonResult flipResult(ComparisonResult result) {
        if (result == ComparisonResult.SAME) return ComparisonResult.COMPLEMENTARY;
        if (result == ComparisonResult.COMPLEMENTARY) return ComparisonResult.SAME;
        return result;
    }
}
