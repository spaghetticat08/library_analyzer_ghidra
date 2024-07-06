package library_analyzer;

import java.util.HashMap;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.script.GhidraScript;

public class LibraryParser {
	
	public HashMap<String, String> build_library_function_byte_mapping(Program currentProgram, TaskMonitor monitor) {
		HashMap<String, String> functionByteMapping = new HashMap<String, String>();
		
		// This function assumes to use the bytes per identified function in Ghidra
		
		// First step is to retrieve all functions in the current opened file
		FunctionManager functionManager = currentProgram.getFunctionManager();
		FunctionIterator functionIterator = functionManager.getFunctions(true);
		
		// Then we iterate through each function and per function retrieve all the bytes
		while (functionIterator.hasNext() && !monitor.isCancelled()) {
			Function function = functionIterator.next();
			String functionBytes = get_bytes_in_function(currentProgram,function);
			String functionName = function.getName();
			
			// We map the retrieved bytes to the function name and save them in the hashmap
			functionByteMapping.put(functionName, functionBytes);
		}			
		return functionByteMapping;
	}
	
	
	public String get_bytes_in_function(Program currentProgram, Function function) {
		String functionBytes = null;
		
		AddressSetView functionBody = function.getBody();
		CodeUnitIterator codeUnits = currentProgram.getListing().getCodeUnits(functionBody, true);
		while (codeUnits.hasNext()) {
			CodeUnit codeUnit = codeUnits.next();
			try {
				byte[] functionByteArray = codeUnit.getBytes();
				
			} catch (MemoryAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		
		
		return functionBytes;
	}

	
}
