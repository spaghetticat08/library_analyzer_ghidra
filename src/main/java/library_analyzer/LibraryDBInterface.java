package library_analyzer;

import java.sql.*;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;


public class LibraryDBInterface {

	public String db_url = "jdbc:sqlite:libraries.db";
	
	public void create_new_db() {
		
		try (var conn = DriverManager.getConnection(db_url)) {
			if (conn != null) {
				var meta = conn.getMetaData();
				System.out.println("A new database has been created with driver " + meta.getDriverName());
			}
		} catch (SQLException e) {
			System.err.println(e.getMessage());
		}
	}
	
	/**
	 * Create the tables required for the database
	 * 
	 */
	public void create_db_tables() {
		
		String sql_query = "CREATE TABLE IF NOT EXISTS libraries"
				+ "(libraryId INTEGER PRIMARY KEY, libraryName TEXT, platformArch TEXT, compiler TEXT, compilerFlags TEXT, "
				+ "headerfiles TEXT);"
				+ "CREATE TABLE IF NOT EXISTS functions"
				+ "(functionId INTEGER PRIMARY KEY, libarayId INTEGER, functionName TEXT, functionBytecode BLOB,"
				+ "FOREIGN KEY(libraryId) REFERENCES libraries(libraryId))";
		
		/** String sql_dummy_values = "INSERT INTO libraries(libraryId, libraryName, platformArch, compiler, compilerFlags, headerfiles"
		*		+ ") VALUES (2, 'dummy_lib', 'dummy_arch', 'dummy_gcc', '-d -u -m -o0', 'path/to/dummy/lib.h');"
		*		+ "INSERT INTO functions(libraryId, functionName, functionBytecode)"
		*		+ " VALUES (2, 'dummy_function', '48 8d 3d d9 2f 00 00 48 8d 05 d2 2f 00 00 48 39 f8')";
		*/
		
		try (var conn = DriverManager.getConnection(db_url);
				var stmt = conn.createStatement()) {
				// create a new table
				stmt.executeUpdate(sql_query);
				
				// TODO: this should be removed once we have made unittests for this interface
				// Insert some dummy values to test if they are added correctly
				// stmt.executeUpdate(sql_dummy_values);
				stmt.close();
				conn.commit();
				
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
	}
	
	/**
	 * 
	 * @param libraryName
	 * @param platformArchitecture
	 * @param compilerType
	 * @param compilerFlags
	 * @param headerFiles
	 */
	public int insert_into_libraries_table(String libraryName, String platformArchitecture, String compilerType, String compilerFlags, String headerFiles) {
		// not all parameters may be known so we give them default values to prevent pollution in the db and also
		// have the option to group those with unknown columns
		// we use this trick because overloading would create a lot of clutter in our code
		// deciding which params are optional is a bit of a grey area but for now we assume that the libraryName and headerFiles 
		// are absolutely required
		Integer rowid = 0;
		if (libraryName == null || headerFiles == null) {
			throw new IllegalArgumentException();
		}
		
		// TODO: this could be likely done more elegantly, using some pattern but I need a Java expert for this
		platformArchitecture = platformArchitecture != null ? platformArchitecture : "null";
		compilerType = compilerType != null ? compilerType: "null";
		compilerFlags = compilerFlags != null ? compilerFlags : "null";
		
		String sql_insert = String.format("INSERT INTO libraries (libraryName, platformArch, compiler, compilerFlags, headerFiles)"
				+ " VALUES ('%s', '%s', '%s', '%s', '%s')", libraryName, platformArchitecture, compilerType, compilerFlags, headerFiles);
		
		String sql_select = "";
		
		try (var conn = DriverManager.getConnection(db_url);
				var stmt = conn.createStatement()) {
				
				stmt.executeUpdate(sql_insert);
				
				ResultSet rs = stmt.executeQuery("SELECT last_insert_rowid()");
				if (!rs.next()) {
					System.out.println("Something went wrong with inserting the data");
					return rowid;
				}
				rowid = rs.getInt("last_insert_rowid()");
				System.out.println("The id of the inserted library is " + rowid);
				
				stmt.close();
				conn.commit();
				conn.close();
			
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
		return rowid;
	}
	
	/**
	 * 
	 * @param libraryId
	 * @param functionName
	 * @param functionBytes
	 * TODO: functionbytes is a BLOB type in the database, I think we likely should use a byte array iso string due to encoding
	 */
	public void insert_into_functions_table(int libraryId, String functionName, String functionBytes) {
		if (libraryId <= 0 || functionName == null || functionBytes == null) {
			throw new IllegalArgumentException();
		}
		
		String sql_insert = String.format("INSERT INTO functions(libraryId, functionName, functionBytecode)"
				+ " VALUES (%d, '%s', '$s')", libraryId, functionName, functionBytes);
		
		try (var conn = DriverManager.getConnection(db_url);
				var stmt = conn.createStatement()) {
				stmt.executeUpdate(sql_insert);
				
				stmt.close();
				conn.commit();
				conn.close();
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
	}
	
	/**
	 *  This function returns the library based on the id. It only returns a set consisting of library id and headerfiles
	 *  TODO: in the future we should support all the info to be supplied back, but that would require us to create an object
	 * @param libraryId
	 * @return
	 */
	public HashMap<Integer, String> get_library_by_id(int libraryId) {
		if (libraryId <= 0) {
			throw new IllegalArgumentException();
		}
		HashMap<Integer, String> libraryid_headerfiles_map = new HashMap<Integer, String>();
		String sql_select = String.format("SELECT * FROM libraries WHERE libraryId=%d", libraryId);
		
		try (var conn = DriverManager.getConnection(db_url);
				var stmt = conn.createStatement()) {
				
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				libraryid_headerfiles_map.put(rs.getInt("libraryId"), rs.getString("headerFiles"));
			}
			rs.close();
			stmt.close();
			conn.close();
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
		return libraryid_headerfiles_map;
	}
	
	
	public int get_linked_libraryid_from_function_id(int functionId) {
		Integer library_id = 0;
		
		String sql_select = String.format("SELECT libraryId FROM functions where functionId=%d", functionId);
		
		try (var conn = DriverManager.getConnection(db_url);
				var stmt = conn.createStatement()) {
			
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				library_id = rs.getInt("libraryId");
			}
			rs.close();
			stmt.close();
			conn.close();
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
		return library_id;
	}
	
	
	/**
	 * This function loads all entries in functions table into a hasmap consisting of the functionId and bytecode
	 * TODO: ideally we would like the function name as well but then we have to extend the hashmap with a nested list or
	 * work with objects. For now the dirty solution is to retrieve a functionname in a seperate function on need-basis
	 * @return
	 */
	public HashMap<Integer, String> load_function_bytes(){
		HashMap<Integer, String> functionid_bytecode_map = new HashMap<Integer, String>();
		
		String sql_select = "SELECT functionId, functionBytecode FROM functions";
		
		try (var conn = DriverManager.getConnection(db_url);
				var stmt = conn.createStatement()) {
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				functionid_bytecode_map.put(rs.getInt("functionId"), rs.getString("functionBytecode"));
			}
			rs.close();
			stmt.close();
			conn.close();
			
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
		
		return functionid_bytecode_map;
	}
	
}
