package com.isteer.cvssanalyser.core.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DbUtil {
	private static Connection con= null;
	
	public Connection getConnection(String url,String username, String password) {
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
