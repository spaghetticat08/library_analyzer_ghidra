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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
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

	//public Program currentProgram = getCurrentProgram();
	public enum AnalyzerTask {
		ANALYZE,
		MATCH
	}
	
	public AnalyzerTask currentAnalyzerOptions = AnalyzerTask.ANALYZE;
		
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

		options.registerOption("Action choice option", false, null,
			"Option description goes here");
		options.registerOption("Analysis action", currentAnalyzerOptions, null, "Analyze the current file and add the identified functions to the database");
		
		optionsChanged(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		currentAnalyzerOptions = options.getEnum("Analysis action", AnalyzerTask.ANALYZE);
	}
	
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		
		// Depending on the option chosen, we will either perform analysis on the current file and add it as library 
		
		return false;
	}
}
