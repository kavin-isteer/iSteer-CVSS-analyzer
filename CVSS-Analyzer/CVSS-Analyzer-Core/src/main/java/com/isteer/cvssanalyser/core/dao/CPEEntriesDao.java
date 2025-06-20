package com.isteer.cvssanalyser.core.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;

public class CPEEntriesDao {

	public List<String> getDistinctVendorsList(Connection con) throws SQLException {
		String sql = "select distinct(vendor) from cpe_entries";
		try (Statement st = con.createStatement(); ResultSet rs = st.executeQuery(sql)) {
			List<String> vendorsList = new ArrayList<>();
			while (rs.next()) {
				vendorsList.add(rs.getString(1));
			}
			return vendorsList;
		}
	}

	/**
	 * public List<CpeEntryModel> getCpeEntriesForVendor(Connection con,
	 * List<String> vendors) throws SQLException { String sql = "SELECT id,
	 * cpe_name, cpe_title, vendor, product, version, update_date, deprecated FROM
	 * cpe_entries WHERE vendor IN ("; for (int i = 0; i < vendors.size(); i++) {
	 * sql += "'" + vendors.get(i) + "'"; if (i != vendors.size() - 1) { sql += ",";
	 * } } sql += ")"; // Engine.getMavenLog().info(sql); try (Statement st =
	 * con.createStatement(); ResultSet rs = st.executeQuery(sql)) {
	 * List<CpeEntryModel> entries = new ArrayList<>(); while (rs.next()) {
	 * CpeEntryModel entry = new CpeEntryModel(); entry.setEntryId(rs.getInt(1));
	 * entry.setCpeName(rs.getString(2)); entry.setCpeTitle(rs.getString(3));
	 * entry.setVendor(rs.getString(4)); entry.setProduct(rs.getString(5));
	 * entry.setVersion(rs.getString(6));
	 * entry.setUpdatedDate(rs.getTimestamp(7).toLocalDateTime());
	 * entry.setDeprecated(rs.getBoolean(8)); entries.add(entry); } return entries;
	 * }
	 **/

	public List<CpeEntryModel> getCpeEntriesForVendor(Connection con, Set<String> vendors) throws SQLException {
		if (vendors == null || vendors.isEmpty()) {
			return Collections.emptyList(); // Return empty if no vendors
		}

		List<CpeEntryModel> entries = new ArrayList<>();

		// Step 1: Create temporary table
		try (Statement stmt = con.createStatement()) {
			// Drop the temporary table if it exists
			stmt.executeUpdate("DROP TABLE IF EXISTS temp_vendors");
			stmt.executeUpdate("CREATE TEMPORARY TABLE temp_vendors (vendors VARCHAR(255) PRIMARY KEY)");
		}

		// Step 2: Insert vendors into temp_vendors
		String insertSql = "INSERT INTO temp_vendors (vendors) VALUES (?)";
		try (PreparedStatement ps = con.prepareStatement(insertSql)) {
			for (String vendor : vendors) {
				ps.setString(1, vendor);
				ps.addBatch();
			}
			ps.executeBatch();
		} catch (Exception e) {
			System.err.println("Error executing query: " + e.getMessage());
		}

		// Step 3: Execute the main JOIN query
		String sql = "SELECT id, cpe_name, cpe_title, vendor, product, version, update_date, deprecated "
				+ "FROM cpe_entries c " + "JOIN temp_vendors v ON c.vendor = v.vendors";

		try (PreparedStatement ps = con.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
//                      System.out.println("15-5");
//          long start = System.currentTimeMillis();
//          try (ResultSet rs = ps.executeQuery()) {
//                              System.out.println("15-6");

			while (rs.next()) {
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
//          }
		} catch (SQLException e) {
			System.err.println("Error executing query: " + e.getMessage());
//          throw e; // Re-throw the exception for further handling
		}

		return entries;
	}

	public List<CpeEntryModel> getAllCpeEntries(Connection con) throws SQLException {
		String sql = "SELECT id, cpe_name, cpe_title, vendor, product, version, update_date, deprecated "
				+ "FROM cpe_entries c ";
		List<CpeEntryModel> entries = new ArrayList<>();
		try (PreparedStatement ps = con.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
			while (rs.next()) {
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
		}
		return entries;
	}

	public List<CpeEntryModel> getCpeEntries(Connection con, int lastId) throws SQLException {
		System.out.println(lastId);
		List<CpeEntryModel> entries = new ArrayList<>();
		String sql = "SELECT id, cpe_name, cpe_title, vendor, product, version, update_date, deprecated FROM cpe_entries WHERE id > ? ORDER BY id LIMIT 100000";

		try (PreparedStatement ps = con.prepareStatement(sql)) {
			ps.setInt(1, lastId);
			try (ResultSet rs = ps.executeQuery()) {
				while (rs.next()) {
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
			}
		} catch (SQLException e) {
			Engine.logger.error("Error fetching CPE entries: " + e.getMessage());
		}
		return entries;
	}
}