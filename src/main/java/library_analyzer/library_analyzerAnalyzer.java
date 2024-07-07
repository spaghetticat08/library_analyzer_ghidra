/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package library_analyzer;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import docking.options.editor.FileChooserEditor;
import docking.options.editor.StringWithChoicesEditor;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.*;
/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class library_analyzerAnalyzer extends AbstractAnalyzer {

	private static final String OPTION_NAME_ACTION_CHOOSER = "Action Chooser";
	private static final String OPTION_DESCRIPTION_ACTION_CHOOSER = "Choose whether to analyze a new library or match the functions";

	private static final String OPTION_NAME_LIBRARY_PATH = "Analyze File Path";
	private static final String OPTION_DESCRIPTION_LIBRARY_PATH = "Path to the library to analyze";
	
	private static final String CHOOSER_ANALYZE = "Analyze";
	private static final String CHOOSER_MATCH = "Match";
	
	private static final String OPTION_NAME_LIBRARY_NAME = "Library Name";
	private static final String OPTION_DESCRIPTION_LIBRARY_NAME = "The name of the library, by default ghidra will use the current file name";
	
	private static final String OPTION_NAME_COMPILER_TYPE = "Compiler";
	private static final String OPTION_DESCRIPTION_COMPILER_TYPE = "The compiler the executable has been compiled with";
	
	private static final String OPTION_NAME_PLATFORM_ARCHITECTURE = "Architecture";
	private static final String OPTION_DESCRIPTION_PLATFORM_ARCHITECTURE = "Architecture that executable runs on";
	
	private static final String OPTION_NAME_COMPILER_FLAGS = "Compiler Flags";
	private static final String OPTION_DESCRIPTION_COMPILER_FLAGS = "The compiler flags that were used to compile this executable";
	
	private static final String OPTION_NAME_HEADER_FILES = "Headerfiles";
	private static final String OPTION_DESCRIPTION_HEADER_FILES = "The name of the headerfiles (#includes) required to compile this library";
	
	//public Program currentProgram = getCurrentProgram();
	public enum AnalyzerTask {
		ANALYZE,
		MATCH
	}
	
	public AnalyzerTask currentAnalyzerOptions = AnalyzerTask.ANALYZE;
	public String analyzerAction = CHOOSER_ANALYZE;
	private File analyzeLibraryPath;
	private String libraryName;
	private String compilerType;
	private String compilerFlags;
	private String platformArchitecture;
	private String headerFiles;
	
		
	public library_analyzerAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("My Analyzer", "Analyzer description goes here", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here
		List<String> chooserList = new ArrayList<>();
		chooserList.add("Analyze library");
		chooserList.add("Match library");
		
		
		options.registerOption(OPTION_NAME_ACTION_CHOOSER, OptionType.STRING_TYPE, CHOOSER_ANALYZE, 
				null, OPTION_DESCRIPTION_ACTION_CHOOSER,() -> new StringWithChoicesEditor(chooserList));
		
		options.registerOption(OPTION_DESCRIPTION_LIBRARY_NAME, program.getName(), null, 
				OPTION_DESCRIPTION_LIBRARY_NAME);
		options.registerOption(OPTION_NAME_PLATFORM_ARCHITECTURE, null, null, OPTION_DESCRIPTION_PLATFORM_ARCHITECTURE);
		options.registerOption(OPTION_NAME_COMPILER_TYPE, null, null, OPTION_DESCRIPTION_COMPILER_TYPE);
		options.registerOption(OPTION_NAME_COMPILER_FLAGS, null, null, OPTION_DESCRIPTION_COMPILER_FLAGS);
		options.registerOption(OPTION_NAME_HEADER_FILES, null, null, OPTION_DESCRIPTION_HEADER_FILES);
	
		// This option might be unnecessary if we allow the analysis of a library only to be performed on the currently opened file in ghidra
		//options.registerOption(OPTION_NAME_LIBRARY_PATH, OptionType.FILE_TYPE, null,
		//		null, OPTION_DESCRIPTION_LIBRARY_PATH, () -> new FileChooserEditor());
		
		optionsChanged(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		analyzerAction = options.getString(OPTION_NAME_ACTION_CHOOSER, analyzerAction);
		//analyzeLibraryPath = options.getFile(OPTION_NAME_LIBRARY_PATH, analyzeLibraryPath);
		libraryName = options.getString(OPTION_NAME_LIBRARY_NAME, libraryName);
		platformArchitecture = options.getString(OPTION_NAME_PLATFORM_ARCHITECTURE, platformArchitecture);
		compilerType = options.getString(OPTION_NAME_COMPILER_TYPE, compilerType);
		compilerFlags = options.getString(OPTION_NAME_COMPILER_FLAGS, compilerFlags);
		headerFiles = options.getString(OPTION_NAME_HEADER_FILES, headerFiles);
		
	}
	
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		
		// Depending on the option chosen, we will either perform analysis on the current file and add it as library 
		
		if (analyzerAction == CHOOSER_ANALYZE) {
			analyze_library_and_store_in_db(program, monitor);
		} else if (analyzerAction == CHOOSER_MATCH) {
			
		} else {
			// no valid action chosen, do nothing
		}
		
		return false;
	}
	
	/**
	 * 
	 * @param program
	 * @param monitor
	 */
	public void analyze_library_and_store_in_db(Program program, TaskMonitor monitor) {
		// Call function to parse all functions and get bytes per function
		HashMap<String, String> function_bytecode_map = new HashMap<String, String> ();
		Integer f_libraryId;
		function_bytecode_map = LibraryParser.build_library_function_byte_mapping(program, monitor);
		// Retrieve the library if it already exists in database
		HashMap<Integer, String> library_includes_map = new HashMap<Integer, String>();
		library_includes_map = LibraryDBInterface.get_library_by_variable_columns(libraryName, platformArchitecture, compilerType, compilerFlags, headerFiles);
		if (library_includes_map.isEmpty()) {
			// If library does not exists, create new library in database
			f_libraryId = LibraryDBInterface.insert_into_libraries_table(libraryName, platformArchitecture, compilerType, compilerFlags, headerFiles);
			// iterate through our hashmap and add all functions
			for (HashMap.Entry<String, String> set : function_bytecode_map.entrySet()) {
				LibraryDBInterface.insert_into_functions_table(f_libraryId, set.getKey(), set.getValue());
			}
		} else {
			HashMap.Entry<Integer, String> entry = library_includes_map.entrySet().iterator().next();
			f_libraryId = entry.getKey();
			
			for (HashMap.Entry<String, String> set : function_bytecode_map.entrySet()) {
				// To prevent duplicate functions we should for every insert first check whether this function already exists.
				if (LibraryDBInterface.check_function_exists(f_libraryId, set.getKey(), set.getValue()) == false) {
					LibraryDBInterface.insert_into_functions_table(f_libraryId, set.getKey(), set.getValue());
				}
			}			 
		}
	}
	
	public void search_function_matches(Program program, TaskMonitor monitor) {
		
		HashMap<String, String> ghidra_function_bytecode_map = new HashMap<String, String>();
		ghidra_function_bytecode_map = LibraryParser.build_library_function_byte_mapping(program, monitor);
		HashMap<Integer, String> db_function_bytecode_map = new HashMap<Integer, String>();
		db_function_bytecode_map = LibraryDBInterface.load_function_bytes();
		
		for (HashMap.Entry<String, String> analysisSet : ghidra_function_bytecode_map.entrySet()) {
			String analysisBytecode = analysisSet.getValue();
			for (HashMap.Entry<Integer, String> referenceSet : db_function_bytecode_map.entrySet()) {
				String referenceBytecode = referenceSet.getValue();
				Integer f_functionId = referenceSet.getKey();
				// do matching here. Still need to figure out how we can do this in most elegant way.
				// TODO: the third parameter should definitely not be hardcoded!
				if (LibraryMatcher.compare_and_match_bytecode(analysisBytecode, referenceBytecode, true)) {
					// function returns true if both bytecodes match
					// we use the referenceset to retrieve the id of the function and with that the linked libraryId
					Integer f_libraryId = LibraryDBInterface.get_linked_libraryid_from_function_id(f_functionId);
					
					// get the functionName from the database
					String f_functionDbName = LibraryDBInterface.get_function_name_by_id(f_functionId);
					// get the libraryName from the database
					String f_libraryDbName = LibraryDBInterface.get_library_name_from_libraryid(f_libraryId);
					// get the library headerfiles from the database
					String f_headerFiles = LibraryDBInterface.get_library_headers_from_libraryid(f_libraryId);
					// report our match
					System.out.println(String.format("Found a function match for %s, this matches to function %s, from library %s, using headerfiles %s", 
							analysisSet.getKey(), f_functionDbName, f_libraryDbName, f_headerFiles));
					
					// TODO: for now we only report our match, later we want to automatically adapt the ghidra listing with the
					// matches. Or make it optional via the GUI.
					// Might also be good to write our match in a file since the terminal in the gui will quickly clog up
					// TODO: write results to a file
					
				}
			}
		}
		
		
	}
}
