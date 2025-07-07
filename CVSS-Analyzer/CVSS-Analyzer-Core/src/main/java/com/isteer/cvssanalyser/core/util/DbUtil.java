package com.isteer.cvssanalyser.core.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.enums.EngineMode;

public class DbUtil {
	private static Connection con= null;
	static String DB_URL = "CVSS_DB_URL";
    static String DB_USERNAME = "CVSS_DB_USERNAME";
    static String DB_PASSWORD = "CVSS_DB_PASSWORD";
    
    
	public Connection getConnection() {
		if(Engine.analysisMode==EngineMode.MAVEN_PLUGIN) {
			try {
				con = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
				return con;
			} catch (SQLException e) {
				e.printStackTrace();
			}
			return con;
		}else {
			String url = System.getenv(DB_URL);
		    String username = System.getenv(DB_USERNAME);
		    String password = System.getenv(DB_PASSWORD);
		    if(url==null || url.isEmpty() ||username==null || username.isEmpty() ||password==null || password.isEmpty()) {
		    	url = PropertyReader.getProperty(DB_URL);
		    	username = PropertyReader.getProperty(DB_USERNAME);
		    	password = PropertyReader.getProperty(DB_PASSWORD);
		    }
		    if(url==null || url.isEmpty() ||username==null || username.isEmpty() ||password==null || password.isEmpty()) {
		    	throw new RuntimeException("Unable to get connection to CVSS database. Credentials error!!");
		    }
		    try {
			if(con!=null && !con.isClosed()) {
				return con;
			}
				con = DriverManager.getConnection(url, username, password);
				return con;
			} catch (SQLException e) {
				e.printStackTrace();
				return null;
			}
		}
	}
	public static void withDbCredentials(String url,String username,String password) {
		DB_URL=url;
		DB_USERNAME=username;
		DB_PASSWORD=password;
	}
}
