package com.isteer.cvssanalyser.core.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.isteer.cvssanalyser.core.enums.HintAddedBy;
import com.isteer.cvssanalyser.core.model.DependencyHintModel;

public class DependencyHintDao {
	public List<DependencyHintModel> getAllDependencyHints(Connection con) {
		String query = "SELECT id,type,match_key,standardized_name,confidence,description,created_at,updated_at,addedBy FROM dependency_hints";
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
				hint.setAddedBy(HintAddedBy.fromId(rs.getInt(9)));
				hints.add(hint);

			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return hints;
	}

	public List<DependencyHintModel> getAllVendorDependencyHints(Connection con, String evidence_type) {
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
				hint.setAddedBy(HintAddedBy.fromId(rs.getInt(9)));
				hints.add(hint);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return hints;
	}

	public List<DependencyHintModel> getAllVendorDependencyHints(Connection con) {
		String query = "SELECT id,type,match_key,standardized_name,confidence,description,created_at,updated_at,evidence_type,addedBy FROM dependency_hints WHERE type = ?";
		List<DependencyHintModel> hints = new ArrayList<>();
		try {
			PreparedStatement psc = con.prepareStatement(query);
			psc.setString(1, "vendor");
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
				hint.setEvidenceType(rs.getString(9));
				hint.setAddedBy(HintAddedBy.fromId(rs.getInt(10)));
				hints.add(hint);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return hints;
	}

	public List<DependencyHintModel> getAllProductDependencyHints(Connection con, String evidence_type) {
		String query = "SELECT id,type,match_key,standardized_name,confidence,description,created_at,updated_at,addedBy FROM dependency_hints WHERE type = ? AND evidence_type=?";
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
				hint.setAddedBy(HintAddedBy.fromId(rs.getInt(9)));
				hints.add(hint);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return hints;
	}

	public int addDependencyHint(Connection con, DependencyHintModel hint) {
		// String query = "INSERT INTO dependency_hints (type, match_key,
		// standardized_name, confidence, description, evidence_type) VALUES
		// (?,?,?,?,?,?)";

		String checkQuery = "SELECT COUNT(*) FROM dependency_hints WHERE type = ? AND match_key = ? AND evidence_type=?";
		String insertQuery = "INSERT INTO dependency_hints (type, match_key, standardized_name, confidence, description, evidence_type,addedBy) VALUES (?, ?, ?, ?, ?, ?,?)";
		String updateQuery = "UPDATE dependency_hints SET standardized_name = ?, confidence = ?, description = ?, evidence_type = ? , addedBy=? WHERE type = ? AND match_key = ?";

		try {
			// Step 1: Check if record exists
			try (PreparedStatement checkStmt = con.prepareStatement(checkQuery)) {
				checkStmt.setString(1, hint.getType());
				checkStmt.setString(2, hint.getMatch_key());
				checkStmt.setString(3, hint.getEvidenceType());

				ResultSet rs = checkStmt.executeQuery();
				if (rs.next() && rs.getInt(1) > 0) {
					// Step 2a: Record exists, perform update
					try (PreparedStatement updateStmt = con.prepareStatement(updateQuery)) {
						updateStmt.setString(1, hint.getStandardized_name());
						updateStmt.setString(2, hint.getConfidence());
						updateStmt.setString(3, hint.getDescription());
						updateStmt.setString(4, hint.getEvidenceType());
						updateStmt.setInt(5, hint.getAddedBy().getId());
						updateStmt.setString(6, hint.getType());
						updateStmt.setString(7, hint.getMatch_key());

						return updateStmt.executeUpdate(); // rows updated
					}
				} else {
					// Step 2b: Record does not exist, perform insert
					try (PreparedStatement insertStmt = con.prepareStatement(insertQuery)) {
						insertStmt.setString(1, hint.getType());
						insertStmt.setString(2, hint.getMatch_key());
						insertStmt.setString(3, hint.getStandardized_name());
						insertStmt.setString(4, hint.getConfidence());
						insertStmt.setString(5, hint.getDescription());
						insertStmt.setString(6, hint.getEvidenceType());
						insertStmt.setInt(7, hint.getAddedBy().getId());

						return insertStmt.executeUpdate(); // rows inserted
					}
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
			return -1;
		}
	}

	public Set<String> getVendorNameForApplication(Connection con, String vendorName) {
		String query = "SELECT id, type, match_key, standardized_name, confidence, description, created_at, updated_at FROM dependency_hints WHERE match_key = ? AND evidence_type = ?";
		Set<String> resolvedVendor = new HashSet<>();

		try (PreparedStatement psc = con.prepareStatement(query)) {
			psc.setString(1, vendorName);
			psc.setString(2, "APPLICATION");
			try (ResultSet rs = psc.executeQuery()) {
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
					resolvedVendor.add(hint.getStandardized_name());
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return resolvedVendor;
	}
}