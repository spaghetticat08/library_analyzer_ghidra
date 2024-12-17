Library_analyzer_ghidra is a Java implementation of a extension that will search for matching functions based on equal bytecode. This is done by first populating a SQ-Lite database with analyzed functions from decompiled programs in Ghidra, and then comparing all database functions with a program that is currently analyzed in Ghidra. The matching algorithm will search for exact bytecode that exactly matches both database function and the analyzed function in the program. There is a slight exception for branching instructions, here the bytes related to the instruction are first changed to always match since branching instructions can vary due to different offset.
This version currently supports Armv6m instruction set, but in the future will be extended to other instruction sets. 

## Requirements
- Ghidra, https://github.com/NationalSecurityAgency/ghidra
  - Ghidra version 10.3 was used to develop this script
- optionally Java jdbc driver to connect with Sqlite database
- Eclipse and GhidraDev extension to export the extension to Ghidra

## How to run
The extension does not have a zip file available to directly import in Ghidra, so you need to either export the package via Eclipse and then use the GhidraDev extension, or open it in Eclipse and execute the Java program directly via Ghidra.

## Usage
