package com.isteer.cvssanalyser.core.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;

public class CPEEntriesDao {
	
	public List<String> getDistinctVendorsList(Connection con) throws SQLException{
		String sql = "select distinct(vendor) from cpe_entries";
		Statement st = con.createStatement();
		ResultSet rs =  st.executeQuery(sql);
		List<String> vendorsList=new ArrayList<>();
		while(rs.next()) {
			vendorsList.add(rs.getString(1));
		}
		return vendorsList;
	}
	
	public List<CpeEntryModel> getCpeEntriesForVendor(Connection con, List<String> vendors) throws SQLException{
		String sql = "SELECT id, cpe_name, cpe_title, vendor, product, version, update_date, deprecated FROM cpe_entries WHERE vendor IN (";
		for(int i=0;i<vendors.size();i++) {
			sql += "'"+vendors.get(i)+"'";
			if(i!=vendors.size()-1) {
				sql +=",";
			}
		}
		sql += ")";
	//	Engine.getMavenLog().info(sql);
		Statement st = con.createStatement();
		ResultSet rs = st.executeQuery(sql);
		List<CpeEntryModel> entries = new ArrayList<>();
		while(rs.next()) {
			CpeEntryModel entry = new CpeEntryModel();
			entry.setEntryId(rs.getInt(1));
			entry.setCpeName(rs.getString(2));
			entry.setCpeTitle(rs.getString(3));
			entry.setVendor(rs.getString(4));
			entry.setProduct(rs.getString(5));
			entry.setVersion(rs.getString(6));
			entry.setUpdatedDate(rs.getTimestamp(7).toLocalDateTime());
			entry.setDeprecated(rs.getBoolean(8));
			entries.add(entry);
		}
		return entries;
	}
}
