import ghidra.program.model.pcode.*;
import ghidra.pcodeCPort.opcodes.OpCode;

/**
 * Simple, direct example of checking if two CBRANCH operations
 * have inverse conditions.
 *
 * This is the minimal code needed to determine the relationship.
 */
public class SimpleInverseCheck {

	/**
	 * Quick check: Are two CBRANCH operations inverses?
	 *
	 * @param cbranch1 First CBRANCH operation
	 * @param cbranch2 Second CBRANCH operation
	 * @return true if they have inverse conditions
	 */
	public static boolean areInverse(PcodeOp cbranch1, PcodeOp cbranch2) {
		// Verify both are CBRANCH
		if (cbranch1.getOpcode() != PcodeOp.CBRANCH ||
			cbranch2.getOpcode() != PcodeOp.CBRANCH) {
			return false;
		}

		// Get the condition varnodes (input[1] for CBRANCH)
		Varnode cond1Varnode = cbranch1.getInput(1);
		Varnode cond2Varnode = cbranch2.getInput(1);

		// Get the operations that define the conditions
		PcodeOp cond1Op = cond1Varnode.getDef();
		PcodeOp cond2Op = cond2Varnode.getDef();

		// Check both conditions are defined by operations
		if (cond1Op == null || cond2Op == null) {
			return false;
		}

		// Convert to OpCode enum
		OpCode opCode1 = OpCode.getOpcode(cond1Op.getOpcode());
		OpCode opCode2 = OpCode.getOpcode(cond2Op.getOpcode());

		// Get the inverse of the first operation
		OpCode invertedOp1 = opCode1.getOpCodeFlip();

		// Check if they're inverses
		if (invertedOp1 == OpCode.CPUI_MAX || invertedOp1 != opCode2) {
			return false;  // Not inverses
		}

		// They have inverse opcodes - now verify operand relationship
		boolean needsSwap = opCode1.getBooleanFlip();

		// Check operand relationship
		if (cond1Op.getNumInputs() >= 2 && cond2Op.getNumInputs() >= 2) {
			Varnode op1Left = cond1Op.getInput(0);
			Varnode op1Right = cond1Op.getInput(1);
			Varnode op2Left = cond2Op.getInput(0);
			Varnode op2Right = cond2Op.getInput(1);

			if (needsSwap) {
				// For < and <=, operands should be swapped
				// (a < b) is inverse of (b >= a) which is INT_SLESSEQUAL(b, a)
				return op1Left.equals(op2Right) && op1Right.equals(op2Left);
			} else {
				// For == and !=, operands should be the same
				// (a == b) is inverse of (a != b)
				return op1Left.equals(op2Left) && op1Right.equals(op2Right);
			}
		}

		return false;
	}

	/**
	 * Enhanced version that provides detailed information
	 */
	public static InverseInfo getInverseInfo(PcodeOp cbranch1, PcodeOp cbranch2) {
		InverseInfo info = new InverseInfo();

		// Verify both are CBRANCH
		if (cbranch1.getOpcode() != PcodeOp.CBRANCH) {
			info.error = "First operation is not CBRANCH";
			return info;
		}
		if (cbranch2.getOpcode() != PcodeOp.CBRANCH) {
			info.error = "Second operation is not CBRANCH";
			return info;
		}

		// Get condition operations
		Varnode cond1Varnode = cbranch1.getInput(1);
		Varnode cond2Varnode = cbranch2.getInput(1);

		PcodeOp cond1Op = cond1Varnode.getDef();
		PcodeOp cond2Op = cond2Varnode.getDef();

		if (cond1Op == null) {
			info.error = "First condition not defined by operation";
			return info;
		}
		if (cond2Op == null) {
			info.error = "Second condition not defined by operation";
			return info;
		}

		// Get opcodes
		OpCode opCode1 = OpCode.getOpcode(cond1Op.getOpcode());
		OpCode opCode2 = OpCode.getOpcode(cond2Op.getOpcode());

		info.condition1 = opCode1;
		info.condition2 = opCode2;

		// Check for inverse
		OpCode invertedOp1 = opCode1.getOpCodeFlip();

		if (invertedOp1 == OpCode.CPUI_MAX) {
			info.error = opCode1.getName() + " has no inverse operation";
			return info;
		}

		if (invertedOp1 != opCode2) {
			info.error = String.format("%s and %s are not inverse operations",
				opCode1.getName(), opCode2.getName());
			return info;
		}

		// They're inverse opcodes
		info.areInverseOpcodes = true;
		info.requiresOperandSwap = opCode1.getBooleanFlip();

		// Check operands
		if (cond1Op.getNumInputs() >= 2 && cond2Op.getNumInputs() >= 2) {
			Varnode op1Left = cond1Op.getInput(0);
			Varnode op1Right = cond1Op.getInput(1);
			Varnode op2Left = cond2Op.getInput(0);
			Varnode op2Right = cond2Op.getInput(1);

			if (info.requiresOperandSwap) {
				info.operandsMatch = op1Left.equals(op2Right) &&
					op1Right.equals(op2Left);
			} else {
				info.operandsMatch = op1Left.equals(op2Left) &&
					op1Right.equals(op2Right);
			}

			info.isComplete = info.operandsMatch;
		}

		return info;
	}

	/**
	 * Result class with detailed information
	 */
	public static class InverseInfo {
		public boolean areInverseOpcodes = false;
		public boolean requiresOperandSwap = false;
		public boolean operandsMatch = false;
		public boolean isComplete = false;
		public OpCode condition1 = null;
		public OpCode condition2 = null;
		public String error = null;

		public boolean areInverse() {
			return isComplete && areInverseOpcodes && operandsMatch;
		}

		@Override
		public String toString() {
			if (error != null) {
				return "Error: " + error;
			}

			if (!areInverse()) {
				return String.format("NOT inverse: %s vs %s",
					condition1 != null ? condition1.getName() : "?",
					condition2 != null ? condition2.getName() : "?");
			}

			return String.format("INVERSE: %s ↔ %s%s",
				condition1.getName(),
				condition2.getName(),
				requiresOperandSwap ? " (operands swapped)" : "");
		}
	}

	/**
	 * Example usage
	 */
	public static void main(String[] args) {
		System.out.println("Simple Inverse Condition Checker");
		System.out.println("=================================\n");

		System.out.println("Usage in Ghidra:");
		System.out.println("-----------------");
		System.out.println();
		System.out.println("// Get two CBRANCH operations from your analysis");
		System.out.println("PcodeOp cbranch1 = ...; // Your first CBRANCH");
		System.out.println("PcodeOp cbranch2 = ...; // Your second CBRANCH");
		System.out.println();
		System.out.println("// Simple check");
		System.out.println("boolean inverse = SimpleInverseCheck.areInverse(cbranch1, cbranch2);");
		System.out.println("if (inverse) {");
		System.out.println("    System.out.println(\"These conditions are inverses!\");");
		System.out.println("}");
		System.out.println();
		System.out.println("// Detailed check");
		System.out.println("InverseInfo info = SimpleInverseCheck.getInverseInfo(cbranch1, cbranch2);");
		System.out.println("System.out.println(info); // Prints detailed relationship");
		System.out.println();

		System.out.println("\nHow it works:");
		System.out.println("--------------");
		System.out.println("1. Extract condition varnodes from each CBRANCH (input[1])");
		System.out.println("2. Get the PcodeOp that defines each condition");
		System.out.println("3. Convert opcodes to OpCode enum");
		System.out.println("4. Use getOpCodeFlip() to get the inverse opcode");
		System.out.println("5. Compare: is opCode2 == opCode1.getOpCodeFlip()?");
		System.out.println("6. Check if operand swap is needed with getBooleanFlip()");
		System.out.println("7. Verify operands match correctly (same or swapped)");
		System.out.println();

		System.out.println("\nExamples of inverse relationships:");
		System.out.println("-----------------------------------");
		System.out.println("INT_EQUAL (a, b)          ↔ INT_NOTEQUAL (a, b)");
		System.out.println("INT_SLESS (a, b)          ↔ INT_SLESSEQUAL (b, a) [SWAPPED]");
		System.out.println("INT_SLESSEQUAL (a, b)     ↔ INT_SLESS (b, a) [SWAPPED]");
		System.out.println("BOOL_NEGATE (x)           ↔ COPY (x)");
		System.out.println();
		System.out.println("The [SWAPPED] tag indicates operands must be in opposite order.");
	}
}
