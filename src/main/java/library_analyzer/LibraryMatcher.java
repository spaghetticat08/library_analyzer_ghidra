package library_analyzer;

public class LibraryMatcher {

	/** TODO: likely we cannot do bytepattern matching using String datatype!
	 * 
	 * @param analysisBytecode
	 * @param referenceBytecode
	 * @param neutralizeBlIns
	 * @return
	 */
	public static boolean compare_and_match_bytecode(String analysisBytecode, String referenceBytecode, boolean neutralizeBlIns) {
		boolean foundMatch = false;
		
		if (neutralizeBlIns == true) {
			// In case of ARM instructions, the BL instructions won't exactly match since the libraries are compiled but not linked
			// this results in an bl instruction without the offset and therefore a slightly different bytecode than in the compiled
			// and linked binary. To solve this, we neutralize these instructions in the analysisBytecode to match with the referenceBytecode
			
			System.out.println("Bytecode before neutralizing the branch link instructions: " + analysisBytecode);
			
			analysisBytecode = analysisBytecode.replaceAll("\\s(f7[\\da-f]f|f00\\d)\\s[\\da-f]{4}", " f7ff fffe");
		
			System.out.println("Bytecode after neutralizing the branch link instructions: " + analysisBytecode);
		}
		
		foundMatch = analysisBytecode.equals(referenceBytecode);
		
		return foundMatch;
	}
	
}
