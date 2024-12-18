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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
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
	
	private static final String OPTION_NAME_FIRST_TIME_DB_SETUP = "Setup database for first time";
	private static final String OPTION_DESCRIPTION_FIRST_TIME_DB_SETUP = "Enable the option to set up the database and the required tables. Only need to run once";
	private static final boolean OPTION_DEFAULT_FIRST_TIME_DB_SETUP = false;
	
	private static final String OPTION_NAME_ACTION_CHOOSER = "Action Chooser";
	private static final String OPTION_DESCRIPTION_ACTION_CHOOSER = "Choose whether to analyze a new library or match the functions";

	private static final String OPTION_NAME_LIBRARY_PATH = "Analyze File Path";
	private static final String OPTION_DESCRIPTION_LIBRARY_PATH = "Path to the library to analyze";
	
	private static final String CHOOSER_ANALYZE = "Analyze library";
	private static final String CHOOSER_MATCH = "Match library";
	
	private static final String OPTION_NAME_LIBRARY_NAME = "Library Name";
	private static final String OPTION_DESCRIPTION_LIBRARY_NAME = "The name of the library, by default the file name";
	
	private static final String OPTION_NAME_COMPILER_TYPE = "Compiler";
	private static final String OPTION_DESCRIPTION_COMPILER_TYPE = "The compiler the executable has been compiled with";
	
	private static final String OPTION_NAME_PLATFORM_ARCHITECTURE = "Architecture";
	private static final String OPTION_DESCRIPTION_PLATFORM_ARCHITECTURE = "Architecture that executable runs on";
	
	private static final String OPTION_NAME_COMPILER_FLAGS = "Compiler Flags";
	private static final String OPTION_DESCRIPTION_COMPILER_FLAGS = "The compiler flags that were used to compile this executable";
	
	private static final String OPTION_NAME_HEADER_FILES = "Headerfiles";
	private static final String OPTION_DESCRIPTION_HEADER_FILES = "The name of the headerfiles (#includes) required to compile this library";
	
	private static final String OPTION_GENERIC_DEFAULT = "generic";
	
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
	private boolean setupDBEnabled = OPTION_DEFAULT_FIRST_TIME_DB_SETUP;
	
		
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
		chooserList.add(CHOOSER_ANALYZE);
		chooserList.add(CHOOSER_MATCH);
		
		options.registerOption(OPTION_NAME_FIRST_TIME_DB_SETUP, setupDBEnabled, null, OPTION_DESCRIPTION_FIRST_TIME_DB_SETUP);				
		options.registerOption(OPTION_NAME_ACTION_CHOOSER, OptionType.STRING_TYPE, CHOOSER_ANALYZE, 
				null, OPTION_DESCRIPTION_ACTION_CHOOSER,() -> new StringWithChoicesEditor(chooserList));
		
		options.registerOption(OPTION_NAME_LIBRARY_NAME, program.getName(), null, 
				OPTION_DESCRIPTION_LIBRARY_NAME);
		options.registerOption(OPTION_NAME_PLATFORM_ARCHITECTURE, OptionType.STRING_TYPE,
				OPTION_GENERIC_DEFAULT, null, OPTION_DESCRIPTION_PLATFORM_ARCHITECTURE);
		options.registerOption(OPTION_NAME_COMPILER_TYPE, OptionType.STRING_TYPE,
				OPTION_GENERIC_DEFAULT, null, OPTION_DESCRIPTION_COMPILER_TYPE);
		options.registerOption(OPTION_NAME_COMPILER_FLAGS, OptionType.STRING_TYPE,
				OPTION_GENERIC_DEFAULT, null, OPTION_DESCRIPTION_COMPILER_FLAGS);
		options.registerOption(OPTION_NAME_HEADER_FILES, OptionType.STRING_TYPE,
				OPTION_GENERIC_DEFAULT, null, OPTION_DESCRIPTION_HEADER_FILES);
	
		// This option might be unnecessary if we allow the analysis of a library only to be performed on the currently opened file in ghidra
		//options.registerOption(OPTION_NAME_LIBRARY_PATH, OptionType.FILE_TYPE, null,
		//		null, OPTION_DESCRIPTION_LIBRARY_PATH, () -> new FileChooserEditor());
		
		optionsChanged(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// TODO: it appears there is a bug with the getString option if the default value is set to null both for setString as well as for
		// registerOption. For now we solve this by initializing default values, but its not ideal since we can not leave fields empty and
		// sort of uninitialize them...
		setupDBEnabled = options.getBoolean(OPTION_NAME_FIRST_TIME_DB_SETUP, setupDBEnabled);
		analyzerAction = options.getString(OPTION_NAME_ACTION_CHOOSER, analyzerAction);
		//analyzeLibraryPath = options.getFile(OPTION_NAME_LIBRARY_PATH, analyzeLibraryPath);
		libraryName = options.getString(OPTION_NAME_LIBRARY_NAME, libraryName);
		//platformArchitecture = options.getString(OPTION_NAME_PLATFORM_ARCHITECTURE, platformArchitecture);
		platformArchitecture = options.getString(OPTION_NAME_PLATFORM_ARCHITECTURE, OPTION_GENERIC_DEFAULT);
		compilerType = options.getString(OPTION_NAME_COMPILER_TYPE, OPTION_GENERIC_DEFAULT);
		compilerFlags = options.getString(OPTION_NAME_COMPILER_FLAGS, OPTION_GENERIC_DEFAULT);
		headerFiles = options.getString(OPTION_NAME_HEADER_FILES, OPTION_GENERIC_DEFAULT);
		
		//System.out.println("Options found: setupDBEnabled = " + setupDBEnabled + "\nanalyzerAction = " + analyzerAction + "\nlibraryName = "
		//		+ libraryName + "\nplatformArchitecture = " + platformArchitecture + "\ncompilerType = " + compilerType + "\ncompilerFlags = "
		//		 + compilerFlags + "\nheaderFiles = " + headerFiles);
		
	}
	
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		boolean analysisSucceeded = false;
		try {
			BufferedWriter outputFile = new BufferedWriter(new FileWriter("library_analyzer_output.txt"));
			
			// if the first time setup option is enabled, we need to setup the DB first
			if (setupDBEnabled == true) {
				outputFile.write("\nFirst time setup of database...\n");
				LibraryDBInterface.create_new_db(outputFile);
				LibraryDBInterface.create_db_tables(outputFile);
			}	
			
			outputFile.write("Starting a new run of library_analyzer....\n");
			outputFile.write("Options provided for this run: \n");
			String optionsString = String.format("analyzerAction = %s\nlibraryName = %s\nplatformArchitecture = %s"
					+ "\ncompilerType = %s\ncompilerFlags = %s\nheaderFiles = %s\n", analyzerAction, libraryName, platformArchitecture,
					compilerType, compilerFlags, headerFiles);
			outputFile.write(optionsString);
			// Depending on the option chosen, we will either perform analysis on the current file and add it as library 
			
			if (analyzerAction == CHOOSER_ANALYZE) {
				LibraryDBInterface.test_db_connection(outputFile);
				analyze_library_and_store_in_db(program, monitor, outputFile);
				analysisSucceeded = true;
			} else if (analyzerAction == CHOOSER_MATCH) {
				LibraryDBInterface.test_db_connection(outputFile);
				search_function_matches(program, monitor, outputFile);
				analysisSucceeded = true;
			} else {
				// no valid action chosen, do nothing
				analysisSucceeded = false;
				outputFile.write("\nNo valid option chosen, skipping the analyzer!");
			}
			
			
			outputFile.close();
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		System.out.println(String.format("Analysis succeeded? %b", analysisSucceeded));
		return analysisSucceeded;
	}
	
	/**
	 * 
	 * @param program
	 * @param monitor
	 * @throws IOException 
	 */
	public void analyze_library_and_store_in_db(Program program, TaskMonitor monitor, BufferedWriter outputFile) throws IOException {
		outputFile.write("Entering function analyze_library_and_store_in_db....\n");
		// Call function to parse all functions and get bytes per function
		HashMap<String, byte[]> function_bytecode_map = new HashMap<String, byte[]> ();
		Integer f_libraryId;
		function_bytecode_map = LibraryParser.build_library_function_byte_mapping(program, monitor, outputFile);
		// Retrieve the library if it already exists in database
		HashMap<Integer, String> library_includes_map = new HashMap<Integer, String>();
		library_includes_map = LibraryDBInterface.get_library_by_variable_columns(libraryName, platformArchitecture, compilerType, compilerFlags, headerFiles, outputFile);
		if (library_includes_map.isEmpty()) {
			// If library does not exists, create new library in database
			f_libraryId = LibraryDBInterface.insert_into_libraries_table(libraryName, platformArchitecture, compilerType, compilerFlags, headerFiles, outputFile);
			// iterate through our hashmap and add all functions
			for (HashMap.Entry<String, byte[]> set : function_bytecode_map.entrySet()) {
				LibraryDBInterface.insert_into_functions_table(f_libraryId, set.getKey(), set.getValue(), outputFile);
			}
		} else {
			HashMap.Entry<Integer, String> entry = library_includes_map.entrySet().iterator().next();
			f_libraryId = entry.getKey();
			
			for (HashMap.Entry<String, byte[]> set : function_bytecode_map.entrySet()) {
				// To prevent duplicate functions we should for every insert first check whether this function already exists.
				if (LibraryDBInterface.check_function_exists(f_libraryId, set.getKey(), set.getValue(), outputFile) == false) {
					LibraryDBInterface.insert_into_functions_table(f_libraryId, set.getKey(), set.getValue(), outputFile);
				}
			}			 
		}
	}
	
	public void search_function_matches(Program program, TaskMonitor monitor, BufferedWriter outputFile) throws IOException {
		outputFile.write("Entering function search_function_matches....\n");
		HashMap<String, byte[]> ghidra_function_bytecode_map = new HashMap<String, byte[]>();
		ghidra_function_bytecode_map = LibraryParser.build_library_function_byte_mapping(program, monitor, outputFile);
		HashMap<Integer, byte[]> db_function_bytecode_map = new HashMap<Integer, byte[]>();
		db_function_bytecode_map = LibraryDBInterface.load_function_bytes(outputFile);
		
		for (HashMap.Entry<String, byte[]> analysisSet : ghidra_function_bytecode_map.entrySet()) {
			byte[] analysisBytecode = analysisSet.getValue();
			for (HashMap.Entry<Integer, byte[]> referenceSet : db_function_bytecode_map.entrySet()) {
				byte[] referenceBytecode = referenceSet.getValue();
				Integer f_functionId = referenceSet.getKey();
				// do matching here. Still need to figure out how we can do this in most elegant way.
				// TODO: the third parameter should definitely not be hardcoded!
				if (LibraryMatcher.compare_and_match_bytes_bytecode(analysisBytecode, referenceBytecode, true)) {
					// function returns true if both bytecodes match
					// we use the referenceset to retrieve the id of the function and with that the linked libraryId
					Integer f_libraryId = LibraryDBInterface.get_linked_libraryid_from_function_id(f_functionId, outputFile);
					
					// get the functionName from the database
					String f_functionDbName = LibraryDBInterface.get_function_name_by_id(f_functionId,outputFile);
					// get the libraryName from the database
					String f_libraryDbName = LibraryDBInterface.get_library_name_from_libraryid(f_libraryId, outputFile);
					// get the library headerfiles from the database
					String f_headerFiles = LibraryDBInterface.get_library_headers_from_libraryid(f_libraryId, outputFile);
					// report our match
					System.out.println(String.format("Found a function match for %s, this matches to function %s, from library %s, using headerfiles %s\n", 
							analysisSet.getKey(), f_functionDbName, f_libraryDbName, f_headerFiles));
					
					outputFile.write(String.format("\nFound a function match for %s, this matches to function %s, from library %s, using headerfiles %s\n", 
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
