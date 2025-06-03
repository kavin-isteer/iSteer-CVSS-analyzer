package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.commons.text.similarity.JaroWinklerSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;

import com.isteer.cvssanalyser.core.dao.CPEEntriesDao;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.model.ScoredCpeEntryModel;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class FuzzySearchTool {
	private DbUtil dbUtil = new DbUtil();
	private final Connection connection = dbUtil.getConnection();
	private CPEEntriesDao entriesDao = new CPEEntriesDao();
	private String[] COMMON_PACKAGE_LITERALS = { "org", "com" };
	private static List<String> vendorNames = new ArrayList<>();


	public void searchForLikelyCpes(DependencyModel dependency) throws SQLException {
		// in line comments---
		Set<String> likelyVendors = new HashSet<>();

		likelyVendors = searchForLikelyVendors(dependency.getVendorEvidences());
		if (likelyVendors.size() == 0) {
			// Engine.logger.info(
			// "Unable to find vendor through fuzzy search for dependency: " +
			// dependency.getDependencyName());
			return;
		}
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		for (Evidence ev : dependency.getProductEvidences()) {
			if (ev.getEvidenceType() == EvidenceType.ARTIFACT_ID) {
				filteredCpes = searchForLikelyProducts(likelyVendors, ev.getEvidence());
			}
		}
		if (filteredCpes.size() > 0) {
			for (CpeEntryModel entry : filteredCpes) {
				CPENameModel wrkCpeNameModel = new CPENameModel();
				wrkCpeNameModel.setProduct(entry.getProduct());
				wrkCpeNameModel.setVendor(entry.getVendor());
				wrkCpeNameModel.setVersion(entry.getVersion());
				wrkCpeNameModel.setValidCpe(true);
				String[] wrkCPELiterals = entry.getCpeName().split(":");
				if (wrkCPELiterals.length > 6) {
					wrkCpeNameModel.setUpdate(wrkCPELiterals[6]);
				}
				// Engine.getMavenLog().info("Adding likely CPE for dependency:
				// "+dependency.getDependencyName()+" - "+wrkCpeNameModel.getCPE23Uri());
				dependency.addLikelyCPEs(wrkCpeNameModel);
			}
			Engine.logger.info("Total likely CPEs found: " + filteredCpes.size());
		}
	}

	public Set<String> searchForLikelyVendors(List<Evidence> evidences) throws SQLException {
		//Retrieve the group Id evidence from the list of evidences.
		String groupId = "";
		for (Evidence ev : evidences) {
			if (ev.getEvidenceType() == EvidenceType.GROUP_ID) {
				groupId = ev.getEvidence();
			}
		}
		if (groupId == null || groupId.equalsIgnoreCase("")) {
			return null;
		}
		// split the group id with dot as the delimiter.
		String[] wrkGroupIdStrings = groupId.split("\\.");
		if(vendorNames.size()==0) {
			Engine.logger.info("Hititng db for distinct vendor names");
			//Retrieve list of distinct vendor names from the database.
			vendorNames = entriesDao.getDistinctVendorsList(connection);
		}
		
		Set<String> likelyMatch = new HashSet<>();
		for (String literal : wrkGroupIdStrings) {
			if (isCommonPackageLiteral(literal)) {
				// Engine.logger.info("Is common package literal :"+literal);
				continue;
			}
			for (String vendor : vendorNames) {
				// Jaro-winkler similarity
				Double similarity = JWMatch(literal, vendor);
				if (similarity.compareTo(Double.valueOf(0.9d)) > 0) {
					likelyMatch.add(vendor);
				}
			}
		}
		if(likelyMatch.size()==0) {
			Engine.logger.warn("Vendor likely match not found. Searching with other evidences");
			for (Evidence ev : evidences) {
				if (ev.getEvidenceType() != EvidenceType.GROUP_ID) {
					for (String vendor : vendorNames) {
						// Jaro-winkler similarity
						Double similarity = JWMatch(ev.getEvidence(), vendor);
						if (similarity.compareTo(Double.valueOf(0.7d)) > 0) {
							likelyMatch.add(vendor);
						}
					}
				}
			}
		}
		Engine.logger.info("Total Vendor likely match found after searching with other evidences: "+likelyMatch.size());
		return likelyMatch;
	}

	public List<CpeEntryModel> searchForLikelyProducts(Set<String> likelyVendors, String artifactId)
			throws SQLException {
		 if (artifactId == null || artifactId.trim().isEmpty()) {
		        return Collections.emptyList();
		 }
		
		// List<CpeEntryModel> filteredCpes = new ArrayList<>();
		List<CpeEntryModel> wrkEntries = entriesDao.getCpeEntriesForVendor(connection, likelyVendors);
		 List<ScoredCpeEntryModel> scoredEntries = new ArrayList<>();
		
		for (CpeEntryModel entry : wrkEntries) {
			// Jaro-winkler similarity
			Double similarity = JWMatch(artifactId, entry.getProduct());
			if (similarity.compareTo(Double.valueOf(0.7d)) > 0) {
				scoredEntries.add(new ScoredCpeEntryModel(entry,similarity));
			}
		}
		
		 // Sort by similarity in descending order
	    scoredEntries.sort((a, b) -> Double.compare(b.similarity, a.similarity));
		return scoredEntries.stream()
				.limit(5)
                .map(scored -> scored.entry)
                .collect(Collectors.toList());
	}

	private boolean isCommonPackageLiteral(String packageLiteral) {
		for (String literal : COMMON_PACKAGE_LITERALS) {
			if (literal.equalsIgnoreCase(packageLiteral)) {
				return true;
			}
		}
		return false;
	}

	// Jaro-Winkler Similarity
	public double JWMatch(String input1, String input2) {
		JaroWinklerSimilarity jaroWinkler = new JaroWinklerSimilarity();
		double similarity = jaroWinkler.apply(input1, input2);
		return similarity;
	}
}
