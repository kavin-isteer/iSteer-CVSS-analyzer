package com.isteer.cvssanalyser.core.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DbUtil {
	private static Connection con= null;
	private static final String DB_URL = "CVSS_DB_URL";
    private static final String DB_USERNAME = "CVSS_DB_USERNAME";
    private static final String DB_PASSWORD = "CVSS_DB_PASSWORD";
    
    
	public Connection getConnection() {
		String url = System.getenv(DB_URL);
	    String username = System.getenv(DB_USERNAME);
	    String password = System.getenv(DB_PASSWORD);
	    if(url==null || url.isEmpty() ||username==null || username.isEmpty() ||password==null || password.isEmpty()) {
	    	throw new RuntimeException("Unable to get connection to CVSS database. Credentials error!!");
	    }
		if(con!=null) {
			return con;
		}
		try {
			this.con = DriverManager.getConnection(url, username, password);
			return con;
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
		}
	}
}
