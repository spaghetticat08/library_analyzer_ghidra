package library_analyzer;

public class LibraryUtilities {
	
	
	/**
	 * 
	 * @param analysisBytecode
	 * @return
	 */
	public static byte[] neutralize_arm_bl_instructions(byte[] analysisBytecode) {
		
		// neutralize the bl instruction bytes. However, in order to find these we have to use a search algorithm
		// these orders need to be reversed
		// f7xf xxxx (where x is either a digit (0-9) or letter from a to f
		// f00x xxxx
		// so reversed order we are looking for elements in our byte array that have 4 elements (4 bytes, bl instruction is always 4 bytes,
		// so that filters out the majority) and the first elements should always start with either {0x.f, 0xf7} (negative offset)
		// or {0x0. 0xf0} (positive offset) where
		// 0 can be either a digit or letter from a-f
		byte[] blInsNegativeOffset = new byte[] {(byte)0x0f, (byte)0x1f, (byte)0x2f, (byte)0x3f, (byte)0x4f, (byte)0x5f, (byte)0x6f,
				(byte)0x7f, (byte)0x8f, (byte)0x9f, (byte)0xaf, (byte)0xbf, (byte)0xcf, (byte)0xdf, (byte)0xef, (byte)0xff};
		byte[] blInsPositiveOffset = new byte[] {(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x05,
				(byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f};
		
		byte[] blInsNeutralized = new byte[] {(byte)0xff, (byte)0xf7, (byte)0xfe, (byte)0xff};
		
		for (int i = 0; i < analysisBytecode.length - 1; i++) {
			for (int j = 0; j < blInsNegativeOffset.length - 1; j++) {
				if (analysisBytecode[i] == blInsNegativeOffset[j]) {
					if (analysisBytecode[i+1] == (byte)0xf7) {
						// we have found a bl instruction with negative offset, which we should neutralize
						analysisBytecode[i] = (byte)0xff;
						analysisBytecode[i + 1] = (byte)0xf7;
						analysisBytecode[i + 2] = (byte) 0xfe;
						analysisBytecode[i + 3] = (byte) 0xff;
						
					}
				}
			}
			for (int k = 0; k < blInsPositiveOffset.length - 1; k++) {
				if (analysisBytecode[i] == blInsPositiveOffset[k]) {
					if (analysisBytecode[i + 1] == (byte)0xf0) {
						// we have found a bl instruction with positive offset, which we should neutralize (we will follow the same pattern
						analysisBytecode[i] = (byte)0xff;
						analysisBytecode[i + 1] = (byte)0xf7;
						analysisBytecode[i + 2] = (byte) 0xfe;
						analysisBytecode[i + 3] = (byte) 0xff;
					}
				}
			}
		}	
		return analysisBytecode;
	}
	
	
}
