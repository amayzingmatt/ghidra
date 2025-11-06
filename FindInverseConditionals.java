// Analyzes a function to find CBRANCH instructions with inverse conditions
// @category Analysis.PCode

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.Address;
import ghidra.pcodeCPort.opcodes.OpCode;
import java.util.*;

/**
 * Script to find and analyze conditional branch instructions (CBRANCH)
 * that have inverse relationships with each other.
 *
 * This is useful for:
 * - Understanding control flow patterns
 * - Identifying complementary branch conditions
 * - Detecting if-else structures
 * - Analyzing optimization opportunities
 */
public class FindInverseConditionals extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			println("No program is open");
			return;
		}

		// Get current function or let user select one
		Function func = getFunctionContaining(currentAddress);
		if (func == null) {
			func = askFunction("Select Function", "Choose a function to analyze:");
			if (func == null) {
				println("No function selected");
				return;
			}
		}

		println("Analyzing function: " + func.getName());
		println("Address: " + func.getEntryPoint());
		println("=" .repeat(60));
		println();

		// Get high-level pcode for the function
		PcodeBlockBasic[] blocks = getPcodeBlocks(func);
		if (blocks == null || blocks.length == 0) {
			println("Could not generate pcode for function");
			return;
		}

		// Find all CBRANCH operations
		List<PcodeOpInfo> cbranchOps = findAllCBranches(blocks);

		println("Found " + cbranchOps.size() + " CBRANCH operations");
		println();

		if (cbranchOps.isEmpty()) {
			println("No conditional branches found in this function");
			return;
		}

		// Display all CBRANCHes with their conditions
		displayCBranchDetails(cbranchOps);
		println();

		// Find inverse relationships
		findAndDisplayInverseRelationships(cbranchOps);
	}

	/**
	 * Get pcode blocks for a function
	 */
	private PcodeBlockBasic[] getPcodeBlocks(Function func) throws Exception {
		// Use simplified pcode from the listing
		InstructionIterator instructions = currentProgram.getListing()
			.getInstructions(func.getBody(), true);

		List<PcodeBlockBasic> blockList = new ArrayList<>();
		PcodeBlockBasic currentBlock = null;

		for (Instruction instr : instructions) {
			// We'll work with individual instruction pcode
			// In a real scenario, you'd want to use HighFunction for proper control flow
		}

		// For this example, let's use a simpler approach
		// Get all instructions and their pcode
		return null; // This would need proper implementation
	}

	/**
	 * Find all CBRANCH operations in the given blocks
	 */
	private List<PcodeOpInfo> findAllCBranches(PcodeBlockBasic[] blocks) {
		List<PcodeOpInfo> cbranchOps = new ArrayList<>();

		// Iterate through all instructions in the function
		Function func = getFunctionContaining(currentAddress);
		InstructionIterator instructions = currentProgram.getListing()
			.getInstructions(func.getBody(), true);

		int instrNum = 0;
		for (Instruction instr : instructions) {
			PcodeOp[] pcode = instr.getPcode();

			for (int i = 0; i < pcode.length; i++) {
				if (pcode[i].getOpcode() == PcodeOp.CBRANCH) {
					cbranchOps.add(new PcodeOpInfo(pcode[i], instr, instrNum, i));
				}
			}
			instrNum++;
		}

		return cbranchOps;
	}

	/**
	 * Display details about each CBRANCH
	 */
	private void displayCBranchDetails(List<PcodeOpInfo> cbranchOps) {
		println("CBRANCH Details:");
		println("-".repeat(60));

		for (int i = 0; i < cbranchOps.size(); i++) {
			PcodeOpInfo info = cbranchOps.get(i);
			PcodeOp cbranch = info.op;

			println(String.format("[%d] At %s (instr #%d, pcode #%d)",
				i, info.instruction.getAddress(), info.instrNum, info.pcodeNum));

			// Get the condition varnode
			Varnode condVarnode = cbranch.getInput(1);
			PcodeOp condOp = condVarnode.getDef();

			if (condOp != null) {
				OpCode opCode = OpCode.getOpcode(condOp.getOpcode());
				println("    Condition: " + opCode.getName());
				println("    " + formatPcodeOp(condOp));
			} else {
				println("    Condition: Direct varnode " + condVarnode);
			}

			// Branch target
			Varnode target = cbranch.getInput(0);
			println("    Target: " + target);
			println();
		}
	}

	/**
	 * Find and display inverse relationships between CBRANCHes
	 */
	private void findAndDisplayInverseRelationships(List<PcodeOpInfo> cbranchOps) {
		println("Inverse Condition Analysis:");
		println("=".repeat(60));
		println();

		int inverseCount = 0;

		// Compare each pair of CBRANCHes
		for (int i = 0; i < cbranchOps.size(); i++) {
			for (int j = i + 1; j < cbranchOps.size(); j++) {
				PcodeOpInfo info1 = cbranchOps.get(i);
				PcodeOpInfo info2 = cbranchOps.get(j);

				InverseResult result = checkInverse(info1.op, info2.op);

				if (result.areInverse) {
					inverseCount++;
					println("INVERSE PAIR FOUND:");
					println("  [" + i + "] " + info1.instruction.getAddress() +
						": " + result.cond1);
					println("  [" + j + "] " + info2.instruction.getAddress() +
						": " + result.cond2);
					println("  Relationship: " + result.description);
					if (result.requiresSwap) {
						println("  Note: Operands are swapped (e.g., a < b vs b >= a)");
					}
					println();
				}
			}
		}

		if (inverseCount == 0) {
			println("No inverse conditional relationships found");
		} else {
			println("Total inverse pairs found: " + inverseCount);
		}
	}

	/**
	 * Check if two CBRANCH operations have inverse conditions
	 */
	private InverseResult checkInverse(PcodeOp cbranch1, PcodeOp cbranch2) {
		// Get condition varnodes
		Varnode cond1Varnode = cbranch1.getInput(1);
		Varnode cond2Varnode = cbranch2.getInput(1);

		PcodeOp cond1Op = cond1Varnode.getDef();
		PcodeOp cond2Op = cond2Varnode.getDef();

		if (cond1Op == null || cond2Op == null) {
			return new InverseResult(false, false, null, null, "");
		}

		OpCode opCode1 = OpCode.getOpcode(cond1Op.getOpcode());
		OpCode opCode2 = OpCode.getOpcode(cond2Op.getOpcode());

		// Check if inverse
		OpCode invertedOp1 = opCode1.getOpCodeFlip();

		if (invertedOp1 == OpCode.CPUI_MAX || invertedOp1 != opCode2) {
			return new InverseResult(false, false, opCode1, opCode2, "");
		}

		// They're inverses
		boolean needsSwap = opCode1.getBooleanFlip();
		String desc = opCode1.getName() + " ↔ " + opCode2.getName();

		// Check if operands match (or are swapped if needed)
		boolean operandsMatch = checkOperandRelationship(cond1Op, cond2Op, needsSwap);

		if (operandsMatch) {
			return new InverseResult(true, needsSwap, opCode1, opCode2, desc);
		}

		return new InverseResult(false, false, opCode1, opCode2,
			"Inverse opcodes but operands don't match");
	}

	/**
	 * Check if operands have the right relationship (same or swapped)
	 */
	private boolean checkOperandRelationship(PcodeOp op1, PcodeOp op2, boolean shouldBeSwapped) {
		if (op1.getNumInputs() < 2 || op2.getNumInputs() < 2) {
			return false;
		}

		Varnode op1Left = op1.getInput(0);
		Varnode op1Right = op1.getInput(1);
		Varnode op2Left = op2.getInput(0);
		Varnode op2Right = op2.getInput(1);

		if (shouldBeSwapped) {
			// Check if swapped: op1(a,b) vs op2(b,a)
			return op1Left.equals(op2Right) && op1Right.equals(op2Left);
		} else {
			// Check if same: op1(a,b) vs op2(a,b)
			return op1Left.equals(op2Left) && op1Right.equals(op2Right);
		}
	}

	/**
	 * Format a PcodeOp for display
	 */
	private String formatPcodeOp(PcodeOp op) {
		StringBuilder sb = new StringBuilder();
		sb.append(op.getMnemonic());

		if (op.getOutput() != null) {
			sb.append(" ").append(op.getOutput());
			sb.append(" = ");
		} else {
			sb.append(" ");
		}

		for (int i = 0; i < op.getNumInputs(); i++) {
			if (i > 0) sb.append(", ");
			sb.append(op.getInput(i));
		}

		return sb.toString();
	}

	// Helper classes

	private static class PcodeOpInfo {
		PcodeOp op;
		Instruction instruction;
		int instrNum;
		int pcodeNum;

		PcodeOpInfo(PcodeOp op, Instruction instruction, int instrNum, int pcodeNum) {
			this.op = op;
			this.instruction = instruction;
			this.instrNum = instrNum;
			this.pcodeNum = pcodeNum;
		}
	}

	private static class InverseResult {
		boolean areInverse;
		boolean requiresSwap;
		OpCode cond1;
		OpCode cond2;
		String description;

		InverseResult(boolean areInverse, boolean requiresSwap, OpCode cond1,
				OpCode cond2, String description) {
			this.areInverse = areInverse;
			this.requiresSwap = requiresSwap;
			this.cond1 = cond1;
			this.cond2 = cond2;
			this.description = description;
		}
	}
}
