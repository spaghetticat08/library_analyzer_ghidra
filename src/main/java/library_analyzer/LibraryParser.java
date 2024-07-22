package library_analyzer;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.script.GhidraScript;

public class LibraryParser {
	
	
	
	public static HashMap<String, byte[]> build_library_function_byte_mapping(Program currentProgram, TaskMonitor monitor, BufferedWriter outputFile) throws IOException {
		HashMap<String, byte[]> functionByteMapping = new HashMap<String, byte[]>();
		
		// This function assumes to use the bytes per identified function in Ghidra
		
		// First step is to retrieve all functions in the current opened file
		FunctionManager functionManager = currentProgram.getFunctionManager();
		FunctionIterator functionIterator = functionManager.getFunctions(true);
		
		// Then we iterate through each function and per function retrieve all the bytes
		while (functionIterator.hasNext() && !monitor.isCancelled()) {
			Function function = functionIterator.next();
			byte[] functionBytes = get_bytes_in_function(currentProgram, function);
			String functionName = function.getName();
			
			// We map the retrieved bytes to the function name and save them in the hashmap
			functionByteMapping.put(functionName, functionBytes);
			outputFile.write("LibraryParser::build_library_function_byte_mapping >> "
					+ "Adding function: " + functionName + "  contains function bytes: " + functionBytes + "\n");
		
		}			
		return functionByteMapping;
	}
	
	
	public static byte[] get_bytes_in_function(Program currentProgram, Function function) {
		ByteArrayOutputStream functionBytecode = new ByteArrayOutputStream();
		
		AddressSetView functionBody = function.getBody();
		CodeUnitIterator codeUnits = currentProgram.getListing().getCodeUnits(functionBody, true);
		while (codeUnits.hasNext()) {
			CodeUnit codeUnit = codeUnits.next();
			try {
				functionBytecode.write(codeUnit.getBytes());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (MemoryAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		byte[] functionBytes = functionBytecode.toByteArray();
		return functionBytes;
	}
	
}
