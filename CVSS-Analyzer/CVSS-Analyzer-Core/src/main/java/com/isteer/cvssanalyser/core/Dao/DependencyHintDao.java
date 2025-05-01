package com.isteer.cvssanalyser.core.Dao;

import java.security.Timestamp;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.isteer.cvssanalyser.core.model.DependencyHintModel;

public class DependencyHintDao {
	public List<DependencyHintModel> getAllDependencyHints(Connection con) {
		String query = "SELECT id,type,match_key,standardized_name,confidence,description,created_at,updated_at FROM dependency_hints";
		List<DependencyHintModel> hints = new ArrayList<>();
		try {
			PreparedStatement psc = con.prepareStatement(query);
			ResultSet rs = psc.executeQuery();
			while (rs.next()) {
				DependencyHintModel hint = new DependencyHintModel();
				hint.setId(rs.getInt(1));
				hint.setType(rs.getString(2));
				hint.setMatch_key(rs.getString(3));
				hint.setStandardized_name(rs.getString(4));
				hint.setConfidence(rs.getString(5));
				hint.setDescription(rs.getString(6));
				if (rs.getTimestamp(7) != null) {
					hint.setCreatedAt(rs.getTimestamp(7).toLocalDateTime());
				}
				if (rs.getTimestamp(8) != null) {
					hint.setUpdatedAt(rs.getTimestamp(8).toLocalDateTime());
				}
				hints.add(hint);
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return hints;
	}

	public List<DependencyHintModel> getAllVendorDependencyHints(Connection con,String evidence_type) {
		String query = "SELECT id,type,match_key,standardized_name,confidence,description,created_at,updated_at FROM dependency_hints WHERE type = ? AND evidence_type=?";
		List<DependencyHintModel> hints = new ArrayList<>();
		try {
			PreparedStatement psc = con.prepareStatement(query);
			psc.setString(1, "vendor");
			psc.setString(2, evidence_type);
			ResultSet rs = psc.executeQuery();
			while (rs.next()) {
				DependencyHintModel hint = new DependencyHintModel();
				hint.setId(rs.getInt(1));
				hint.setType(rs.getString(2));
				hint.setMatch_key(rs.getString(3));
				hint.setStandardized_name(rs.getString(4));
				hint.setConfidence(rs.getString(5));
				hint.setDescription(rs.getString(6));
				if (rs.getTimestamp(7) != null) {
					hint.setCreatedAt(rs.getTimestamp(7).toLocalDateTime());
				}
				if (rs.getTimestamp(8) != null) {
					hint.setUpdatedAt(rs.getTimestamp(8).toLocalDateTime());
				}
				hints.add(hint);
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return hints;
	}
	
	public List<DependencyHintModel> getAllProductDependencyHints(Connection con,String evidence_type) {
		String query = "SELECT id,type,match_key,standardized_name,confidence,description,created_at,updated_at FROM dependency_hints WHERE type = ? AND evidence_type=?";
		List<DependencyHintModel> hints = new ArrayList<>();
		try {
			PreparedStatement psc = con.prepareStatement(query);
			psc.setString(1, "product");
			psc.setString(2, evidence_type);
			ResultSet rs = psc.executeQuery();
			while (rs.next()) {
				DependencyHintModel hint = new DependencyHintModel();
				hint.setId(rs.getInt(1));
				hint.setType(rs.getString(2));
				hint.setMatch_key(rs.getString(3));
				hint.setStandardized_name(rs.getString(4));
				hint.setConfidence(rs.getString(5));
				hint.setDescription(rs.getString(6));
				if (rs.getTimestamp(7) != null) {
					hint.setCreatedAt(rs.getTimestamp(7).toLocalDateTime());
				}
				if (rs.getTimestamp(8) != null) {
					hint.setUpdatedAt(rs.getTimestamp(8).toLocalDateTime());
				}
				hints.add(hint);
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return hints;
	}
}
