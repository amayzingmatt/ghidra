import ghidra.program.model.pcode.*;
import ghidra.pcodeCPort.opcodes.OpCode;

/**
 * Utility class to analyze and identify inverse conditional relationships
 * between CBRANCH instructions in Ghidra's Pcode.
 *
 * A CBRANCH operation branches if its condition input evaluates to true.
 * This class determines if two CBRANCHs have inverse (opposite) conditions.
 *
 * Example inverse conditions:
 *   - if (a == b) vs if (a != b)
 *   - if (a < b) vs if (a >= b)  [Note: requires operand swap]
 *   - if (x) vs if (!x)
 */
public class ConditionalInverseAnalyzer {

	/**
	 * Result of comparing two conditional branch operations
	 */
	public static class InverseConditionResult {
		/** True if the conditions are inverses of each other */
		public final boolean areInverse;

		/** True if operands must be swapped to achieve the inverse relationship */
		public final boolean requiresOperandSwap;

		/** Description of the relationship */
		public final String description;

		/** The first condition's opcode */
		public final OpCode condition1;

		/** The second condition's opcode */
		public final OpCode condition2;

		public InverseConditionResult(boolean areInverse, boolean requiresOperandSwap,
				String description, OpCode cond1, OpCode cond2) {
			this.areInverse = areInverse;
			this.requiresOperandSwap = requiresOperandSwap;
			this.description = description;
			this.condition1 = cond1;
			this.condition2 = cond2;
		}

		@Override
		public String toString() {
			if (!areInverse) {
				return String.format("NOT inverse: %s vs %s - %s",
					condition1, condition2, description);
			}
			return String.format("INVERSE: %s vs %s - %s%s",
				condition1, condition2, description,
				requiresOperandSwap ? " [operands swapped]" : "");
		}
	}

	/**
	 * Determines if two CBRANCH operations have inverse conditions.
	 *
	 * This method analyzes the condition varnodes that feed into each CBRANCH
	 * and determines if they represent inverse logical conditions.
	 *
	 * @param cbranch1 First CBRANCH PcodeOp to compare
	 * @param cbranch2 Second CBRANCH PcodeOp to compare
	 * @return InverseConditionResult describing the relationship
	 */
	public static InverseConditionResult areInverseConditions(PcodeOp cbranch1, PcodeOp cbranch2) {
		// Validate inputs are CBRANCH operations
		if (cbranch1.getOpcode() != PcodeOp.CBRANCH) {
			throw new IllegalArgumentException("First operation is not a CBRANCH: " +
				cbranch1.getMnemonic());
		}
		if (cbranch2.getOpcode() != PcodeOp.CBRANCH) {
			throw new IllegalArgumentException("Second operation is not a CBRANCH: " +
				cbranch2.getMnemonic());
		}

		// Get the condition varnodes (input[1] for CBRANCH)
		// CBRANCH format: input[0] = destination, input[1] = condition
		Varnode cond1Varnode = cbranch1.getInput(1);
		Varnode cond2Varnode = cbranch2.getInput(1);

		// Get the PcodeOp that defines each condition
		PcodeOp cond1Op = cond1Varnode.getDef();
		PcodeOp cond2Op = cond2Varnode.getDef();

		if (cond1Op == null) {
			return new InverseConditionResult(false, false,
				"First condition is not defined by a PcodeOp (may be input/constant)",
				null, null);
		}
		if (cond2Op == null) {
			return new InverseConditionResult(false, false,
				"Second condition is not defined by a PcodeOp (may be input/constant)",
				null, null);
		}

		// Convert to OpCode enum for analysis
		OpCode opCode1 = OpCode.getOpcode(cond1Op.getOpcode());
		OpCode opCode2 = OpCode.getOpcode(cond2Op.getOpcode());

		// Check if they're inverse operations
		return compareConditionOpcodes(opCode1, opCode2, cond1Op, cond2Op);
	}

	/**
	 * Compares two condition opcodes to determine if they're inverses.
	 * Also checks if operands need to be swapped for proper inverse relationship.
	 *
	 * @param opCode1 First condition opcode
	 * @param opCode2 Second condition opcode
	 * @param op1 First PcodeOp (for operand checking)
	 * @param op2 Second PcodeOp (for operand checking)
	 * @return Result describing the inverse relationship
	 */
	private static InverseConditionResult compareConditionOpcodes(OpCode opCode1, OpCode opCode2,
			PcodeOp op1, PcodeOp op2) {

		// Get the inverse of the first opcode
		OpCode invertedOp1 = opCode1.getOpCodeFlip();

		// Check if CPUI_MAX (invalid/no inverse)
		if (invertedOp1 == OpCode.CPUI_MAX) {
			return new InverseConditionResult(false, false,
				opCode1 + " does not have an inverse operation", opCode1, opCode2);
		}

		// Check if they're inverses
		boolean areInverse = (invertedOp1 == opCode2);

		if (!areInverse) {
			return new InverseConditionResult(false, false,
				"Conditions are not inverses", opCode1, opCode2);
		}

		// They're inverses! Now check if operand swap is required
		boolean needsSwap = opCode1.getBooleanFlip();

		// If swap is needed, verify the operands are actually swapped
		if (needsSwap && op1 != null && op2 != null) {
			boolean operandsSwapped = checkOperandsSwapped(op1, op2);

			String desc = String.format("Inverse conditions: %s ↔ %s",
				opCode1.getName(), opCode2.getName());

			if (!operandsSwapped) {
				desc += " (WARNING: operands should be swapped but aren't)";
			}

			return new InverseConditionResult(true, needsSwap, desc, opCode1, opCode2);
		}

		// Simple inverse (no swap needed)
		String desc = String.format("Inverse conditions: %s ↔ %s",
			opCode1.getName(), opCode2.getName());
		return new InverseConditionResult(true, needsSwap, desc, opCode1, opCode2);
	}

	/**
	 * Checks if the operands of two comparison operations are swapped.
	 *
	 * For inverse comparisons like < and >=, the operands should be reversed:
	 *   (a < b) is inverse of (b >= a)
	 *
	 * @param op1 First comparison operation
	 * @param op2 Second comparison operation
	 * @return true if operands are swapped
	 */
	private static boolean checkOperandsSwapped(PcodeOp op1, PcodeOp op2) {
		// Both should have 2 inputs for comparison
		if (op1.getNumInputs() < 2 || op2.getNumInputs() < 2) {
			return false;
		}

		Varnode op1Left = op1.getInput(0);
		Varnode op1Right = op1.getInput(1);
		Varnode op2Left = op2.getInput(0);
		Varnode op2Right = op2.getInput(1);

		// Check if op1's left == op2's right AND op1's right == op2's left
		return op1Left.equals(op2Right) && op1Right.equals(op2Left);
	}

	/**
	 * Example usage and test method
	 */
	public static void main(String[] args) {
		System.out.println("Conditional Inverse Analyzer");
		System.out.println("============================\n");

		// Example: Showing inverse relationships
		System.out.println("Inverse Condition Mappings:");
		System.out.println("---------------------------");

		OpCode[] testOps = {
			OpCode.CPUI_INT_EQUAL,
			OpCode.CPUI_INT_NOTEQUAL,
			OpCode.CPUI_INT_SLESS,
			OpCode.CPUI_INT_SLESSEQUAL,
			OpCode.CPUI_INT_LESS,
			OpCode.CPUI_INT_LESSEQUAL,
			OpCode.CPUI_BOOL_NEGATE,
			OpCode.CPUI_FLOAT_EQUAL,
			OpCode.CPUI_FLOAT_LESS
		};

		for (OpCode op : testOps) {
			OpCode inverse = op.getOpCodeFlip();
			boolean needsSwap = op.getBooleanFlip();

			String swapNote = needsSwap ? " [SWAP OPERANDS]" : "";
			System.out.printf("  %-20s ↔ %-20s%s\n",
				op.getName(),
				inverse == OpCode.CPUI_MAX ? "NO INVERSE" : inverse.getName(),
				swapNote);
		}

		System.out.println("\nNotes:");
		System.out.println("------");
		System.out.println("Operations marked [SWAP OPERANDS] require parameter reordering:");
		System.out.println("  (a < b) inverts to (b >= a) - note operand positions");
		System.out.println("  INT_SLESS (a, b) ↔ INT_SLESSEQUAL (b, a)");
	}
}
