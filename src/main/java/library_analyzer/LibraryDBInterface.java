package library_analyzer;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.sql.*;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;


public class LibraryDBInterface {

	public static final String db_url = "jdbc:sqlite:libraries.db";
	
	public static void create_new_db(BufferedWriter outputFile) throws IOException {
		
		try (Connection conn = DriverManager.getConnection(db_url)) {
			if (conn != null) {
				DatabaseMetaData meta = conn.getMetaData();
				outputFile.write("\nA new database has been created with driver " + meta.getDriverName());
			}
		} catch (SQLException e) {
			printSQLException(e);
		}
	}
	
	
	public static boolean test_db_connection(BufferedWriter outputFile) throws IOException {
		
		try (Connection conn = DriverManager.getConnection(db_url)) {
			outputFile.write("\nConnected to database");

			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
			return false;
		}
		
		return true;
	}
	
	
	/**
	 * Create the tables required for the database
	 * 
	 */
	public static void create_db_tables(BufferedWriter outputFile) throws IOException {
		
		outputFile.write("\nCreating the db tables...");
		
		String sql_query_libraries = "CREATE TABLE IF NOT EXISTS libraries"
				+ "(libraryId INTEGER PRIMARY KEY, libraryName TEXT, platformArch TEXT, compiler TEXT, compilerFlags TEXT, "
				+ "headerFiles TEXT)";
				
		String sql_query_functions =  "CREATE TABLE IF NOT EXISTS functions"
				+ "(functionId INTEGER PRIMARY KEY, libraryId INTEGER, functionName TEXT, functionBytecode BLOB,"
				+ "FOREIGN KEY(libraryId) REFERENCES libraries(libraryId))";
		
		/** String sql_dummy_values = "INSERT INTO libraries(libraryId, libraryName, platformArch, compiler, compilerFlags, headerfiles"
		*		+ ") VALUES (2, 'dummy_lib', 'dummy_arch', 'dummy_gcc', '-d -u -m -o0', 'path/to/dummy/lib.h');"
		*		+ "INSERT INTO functions(libraryId, functionName, functionBytecode)"
		*		+ " VALUES (2, 'dummy_function', '48 8d 3d d9 2f 00 00 48 8d 05 d2 2f 00 00 48 39 f8')";
		*/
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
				// create a new table
				stmt.execute(sql_query_libraries);
				stmt.execute(sql_query_functions);
				
				// TODO: this should be removed once we have made unittests for this interface
				// Insert some dummy values to test if they are added correctly
				// stmt.executeUpdate(sql_dummy_values);
				stmt.close();
				//conn.commit();
				conn.close();
				outputFile.write("\nSuccesfully created tables!");
				
		} catch (SQLException e) {
			printSQLException(e);
		}
	}
	
	/**
	 * 
	 * @param libraryName
	 * @param platformArchitecture
	 * @param compilerType
	 * @param compilerFlags
	 * @param headerFiles
	 * @throws IOException 
	 */
	public static int insert_into_libraries_table(String libraryName, String platformArchitecture, String compilerType, String compilerFlags, String headerFiles, BufferedWriter outputFile) throws IOException {
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
		
		outputFile.write(String.format("\ninsert_into_libraries_table >> insert the following SQL command %s", sql_insert));
		
		String sql_select = "";
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
				
				stmt.execute(sql_insert);
				
				ResultSet rs = stmt.executeQuery("SELECT last_insert_rowid()");
				if (!rs.next()) {
					System.out.println("Something went wrong with inserting the data");
					return rowid;
				}
				rowid = rs.getInt("last_insert_rowid()");
				outputFile.write(String.format("\ninsert_into_libraries_table::The id of the inserted library is %d", rowid));
				
				stmt.close();
				//conn.commit();
				conn.close();
			
		} catch (SQLException e) {
			printSQLException(e);
		}
		return rowid;
	}
	
	/**
	 * 
	 * @param libraryId
	 * @param functionName
	 * @param functionBytes
	 * TODO: functionbytes is a BLOB type in the database, I think we likely should use a byte array iso string due to encoding
	 * @throws IOException 
	 */
	public static void insert_into_functions_table(int libraryId, String functionName, byte[] functionBytes, BufferedWriter outputFile) throws IOException {
		if (libraryId <= 0 || functionName == null || functionBytes == null) {
			throw new IllegalArgumentException();
		}
		
		outputFile.write(String.format("\ninsert_into_functions_table::received parameters %d, %s %s", libraryId, functionName, Hex.encodeHexString(functionBytes)));
		
		String sql_insert = "INSERT INTO functions(libraryId, functionName, functionBytecode) VALUES (?,?,?)";
		
		
		try (Connection conn = DriverManager.getConnection(db_url);
			PreparedStatement pstmt = conn.prepareStatement(sql_insert)) {
				
			pstmt.setInt(1, libraryId);
			pstmt.setString(2, functionName);
			pstmt.setBytes(3, functionBytes);
			outputFile.write(String.format("\ninsert_into_functions_table::insert the following SQL preparedstatement %s", pstmt.toString()));
			pstmt.executeUpdate();
				
			pstmt.close();
			//conn.commit();
			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
		}
	}
	
	/**
	 *  This function returns the library based on the id. It only returns a set consisting of library id and headerfiles
	 *  TODO: in the future we should support all the info to be supplied back, but that would require us to create an object
	 * @param libraryId
	 * @return
	 * @throws IOException 
	 */
	public static HashMap<Integer, String> get_library_by_id(int libraryId, BufferedWriter outputFile) throws IOException {
		if (libraryId <= 0) {
			throw new IllegalArgumentException();
		}
		HashMap<Integer, String> libraryid_headerfiles_map = new HashMap<Integer, String>();
		String sql_select = String.format("SELECT * FROM libraries WHERE libraryId=%d", libraryId);
		
		outputFile.write(String.format("\nget_library_by_id::execute the following SQL command %s", sql_select));
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
				
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				int rs_libraryId = rs.getInt("libraryId");
				String rs_headerFiles = rs.getString("headerFiles");
				libraryid_headerfiles_map.put(rs_libraryId, rs_headerFiles);
				outputFile.write(String.format("\nget_library_by_id::Found library %d with headerfiles %s", rs_libraryId, rs_headerFiles));
			}
			
			rs.close();
			stmt.close();
			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
		}
		return libraryid_headerfiles_map;
	}
	

	/**
	 * This function returns the library (if found), based on the given parameters. So this method supports different combinations of
	 * the parameters supplied, whether it is only one, two or all of them. The requirement is at least one parameter. The more paramaters
	 * supplied, the more likely a library is found if there is any. This function is made because sometimes we want to find the library in the
	 * database but we might not have the id.
	 * @param libraryName (Optional)
	 * @param platformArch (Optional)
	 * @param compilerType (Optional)
	 * @param compilerFlags (Optional)
	 * @param headerFiles (Optional)
	 * @return a Hashmap with the libraryId and headerFiles
	 * @throws IOException 
	 */
	public static HashMap<Integer, String> get_library_by_variable_columns(String libraryName, String platformArch, String compilerType, String compilerFlags, String headerFiles, BufferedWriter outputFile) throws IOException {		
		HashMap<Integer, String> libraryid_headerfiles_map = new HashMap<Integer, String>();
		
		String base_query = "SELECT libraryId, headerFiles FROM libraries";
		List<String> clauses = new ArrayList<String>();
		List<Object> parameters = new ArrayList<Object>();
		// TODO: this could be done much better using the builder pattern
		if (libraryName != null) {
			clauses.add("libraryName = ?");
			parameters.add(libraryName);
		}
		if (platformArch != null) {
			clauses.add("platformArch = ?");
			parameters.add(platformArch);
		}
		if (compilerType != null) {
			clauses.add("compiler = ?");
			parameters.add(platformArch);
		}
		if (compilerFlags != null) {
			clauses.add("compilerFlags = ?");
			parameters.add(compilerFlags);
		}
		if (headerFiles != null) {
			clauses.add("headerFiles = ?");
			parameters.add(headerFiles);
		}
		
		if (!clauses.isEmpty()) {
			base_query += " WHERE " + StringUtils.join(clauses, " AND ");
		}
		
		outputFile.write(String.format("\nget_library_by_variable_columns::execute the following SQL command %s", base_query));
		
		try (Connection conn = DriverManager.getConnection(db_url);
				PreparedStatement ps = conn.prepareStatement(base_query)) {
			for (int i = 0; i < parameters.size(); i++) {
				ps.setObject(i + 1, parameters.get(i));
			}
			
			ResultSet rs = ps.executeQuery();
			while (rs.next() ) {
				int rs_libraryId = rs.getInt("libraryId");
				String rs_headerFiles = rs.getString("headerFiles");
				libraryid_headerfiles_map.put(rs_libraryId, rs_headerFiles);
				outputFile.write(String.format("\nget_library_by_variable_columns::Found library %d with headerfiles %s", rs_libraryId, rs_headerFiles));
			}
			
			rs.close();
			ps.close();
			conn.close();
			
		} catch (SQLException e) {
			printSQLException(e);
		}
		return libraryid_headerfiles_map;
	}
	
	
	/**
	 * This function returns the libraryId that is linked to the functionId
	 * @param functionId An integer that is a unique id to identify a function in the database
	 * @return An integer that represents the libraryId
	 * @throws IOException 
	 */
	public static int get_linked_libraryid_from_function_id(int functionId, BufferedWriter outputFile) throws IOException {
		Integer library_id = 0;
		
		String sql_select = String.format("SELECT libraryId FROM functions where functionId=%d", functionId);
		
		outputFile.write(String.format("\nget_linked_libraryid_from_function_id::execute the SQL command %s", sql_select));
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
			
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				library_id = rs.getInt("libraryId");
				outputFile.write(String.format("\nget_linked_libraryid_from_function_id::found libraryId %d", library_id));
			}
			rs.close();
			stmt.close();
			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
		}
		return library_id;
	}
	
	/** Function to retrieve the libraryName based on the libraryId
	 * 
	 * @param libraryId An integer that represents the libraryId
	 * @return A String that represents the libraryName corresponding to the libraryId
	 * @throws IOException 
	 */
	public static String get_library_name_from_libraryid(int libraryId, BufferedWriter outputFile) throws IOException {
		String libraryName = null;

		String sql_select = String.format("SELECT libraryName FROM libraries WHERE libraryId=%d", libraryId);
		
		outputFile.write(String.format("\nget_library_name_from_libraryid::execute the SQL command %s", sql_select));
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				libraryName = rs.getString("libraryName");
				outputFile.write(String.format("\nget_linked_libraryid_from_function_id::Found libraryName %s", libraryName));
			}
			rs.close();
			stmt.close();
			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
		}
		return libraryName;
	}
	
	
	/** Function to retrieve the headerFiles based on the libraryId
	 * 
	 * @param libraryId Integer that represents the libraryId
	 * @return String that represents the include headerFiles corresponding to the libraryId
	 * @throws IOException 
	 */
	public static String get_library_headers_from_libraryid(int libraryId, BufferedWriter outputFile) throws IOException {
		String libraryHeaders = null;

		String sql_select = String.format("SELECT headerFiles FROM libraries WHERE libraryId=%d", libraryId);
		
		outputFile.write(String.format("\nget_library_headers_from_libraryid::execute the SQL command %s", sql_select));
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				libraryHeaders = rs.getString("headerFiles");
				outputFile.write(String.format("\nget_linked_libraryid_from_function_id::Found the libraryHeaders %s", libraryHeaders));
			}
			rs.close();
			stmt.close();
			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
		}
		return libraryHeaders;
	}
	
	/**
	 * 
	 * @param libraryId
	 * @param functionName
	 * @param functionBytecode
	 * @return
	 * @throws IOException 
	 */
	public static boolean check_function_exists(Integer libraryId, String functionName, byte[] functionBytecode, BufferedWriter outputFile) throws IOException {
		boolean functionExists = false;
		
		String sql_select = "SELECT functionId FROM functions WHERE libraryId=? AND functionName=? AND functionBytecode=?";
		
		outputFile.write(String.format("\ncheck_function_exists::execute the SQL command %s", sql_select));
		
		try (Connection conn = DriverManager.getConnection(db_url);
		
			PreparedStatement pstmt = conn.prepareStatement(sql_select)) {
			pstmt.setInt(1, libraryId);
			pstmt.setString(2, functionName);
			pstmt.setBinaryStream(3, new ByteArrayInputStream(functionBytecode));
			
			ResultSet rs = pstmt.executeQuery();
			if (rs.next()) {
				functionExists = true;
				outputFile.write(String.format("\nget_linked_libraryid_from_function_id::function found %b", functionExists));
			}
			
			rs.close();
			pstmt.close();
			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
		}
		
		return functionExists;
	}
	
	/**
	 * This function loads all entries in functions table into a hasmap consisting of the functionId and bytecode
	 * TODO: ideally we would like the function name as well but then we have to extend the hashmap with a nested list or
	 * work with objects. For now the dirty solution is to retrieve a functionname in a seperate function on need-basis
	 * @return
	 * @throws IOException 
	 */
	public static HashMap<Integer, byte[]> load_function_bytes(BufferedWriter outputFile) throws IOException{
		HashMap<Integer, byte[]> functionid_bytecode_map = new HashMap<Integer, byte[]>();
		
		String sql_select = "SELECT functionId, functionBytecode FROM functions";
		
		outputFile.write(String.format("\nload_function_bytes::execute the SQL command %s", sql_select));
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while (rs.next()) {
				functionid_bytecode_map.put(rs.getInt("functionId"), rs.getBytes("functionBytecode"));
				//Blob blob = rs.getBlob("functionBytecode");
				//functionid_bytecode_map.put(rs.getInt("functionId"), blob.getBytes(1L,(int)blob.length()));
				//outputFile.write(String.format("load_function_bytes::Found the following functionId %d with bytecode %x", ));
			}
			rs.close();
			stmt.close();
			conn.close();
			
		} catch (SQLException e) {
			printSQLException(e);
		}
		
		return functionid_bytecode_map;
	}
	
	
	public static String get_function_name_by_id(Integer functionId, BufferedWriter outputFile) throws IOException {
		String functionName = null;
	
		String sql_select = String.format("SELECT functionName FROM functions WHERE functionId=%d", functionId);
		outputFile.write(String.format("\nget_function_name_by_id::execute the SQL command %s", sql_select));
		
		try (Connection conn = DriverManager.getConnection(db_url);
				Statement stmt = conn.createStatement()) {
			ResultSet rs = stmt.executeQuery(sql_select);
			
			while(rs.next() ) {
				functionName = rs.getString("functionName");
				outputFile.write(String.format("\nget_function_name_by_id::Found functionName %s", functionName));
			}
			rs.close();
			stmt.close();
			conn.close();
		} catch (SQLException e) {
			printSQLException(e);
		}
		
		return functionName;
	}
	
	
	public static void printSQLException(SQLException ex) {
		for (Throwable e : ex) {
			if (e instanceof SQLException) {
				e.printStackTrace(System.err);
				System.err.println("SQLState: " + ((SQLException)e).getSQLState());
				
				System.err.println("Error Code: " + ((SQLException)e).getErrorCode());
				
				System.err.println("Message: " + e.getMessage());
				
				Throwable t = ex.getCause();
				while(t != null) {
					System.out.println("Cause: " + t);
					t = t.getCause();
				
				}
			}
		}
	}
	
}
