package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.text.similarity.JaroWinklerSimilarity;

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

	/**
     * Given a DependencyModel, attempts to find likely matching CPE entries
     * based on vendor and product evidences extracted from the dependency.
     * 
     * @param dependency DependencyModel to search likely CPEs for
     * @throws SQLException on DB errors
     */
	public void searchForLikelyCpes(DependencyModel dependency) throws SQLException {
		Set<String> likelyVendors = new HashSet<>();
		//filter out likely vendors from the list of vendor evidences
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
				//Search for CPE entries with likely product from the filtered likely vendors list
				filteredCpes = searchForLikelyProducts(likelyVendors, ev.getEvidence());
			}
		}
		//Create CPE entry model for each filtered CPE
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
	
	 /**
     * Searches for likely matching vendors based on evidence strings,
     * primarily the groupId from Maven coordinates.
     * 
     * @param evidences List of Evidence objects related to vendor info
     * @return Set of likely matching vendor names
     * @throws SQLException on DB errors
     */
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
			//Engine.logger.info("Hititng db for distinct vendor names");
			//Retrieve list of distinct vendor names from the CPE dictionary database.
			vendorNames = entriesDao.getDistinctVendorsList(connection);
		}
		
		Set<String> likelyMatch = new HashSet<>();
		for (String literal : wrkGroupIdStrings) {
			//If the literal is a common package name ignore it.
			if (isCommonPackageLiteral(literal)) {
				// Engine.logger.info("Is common package literal :"+literal);
				continue;
			}
			for (String vendor : vendorNames) {
				// Jaro-winkler similarity
				//If the literal matches with any of the vendor names from the CPE dictionary, add that to likely match.
				Double similarity = JWMatch(literal, vendor);
				if (similarity.compareTo(Double.valueOf(0.9d)) > 0) {
					likelyMatch.add(vendor);
				}
			}
		}
		//If vendor likely match not found with Group Artifact Verison info the iterate through other evidences and search for likely matches.
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
	
	/**
     * Searches for likely matching products for the given artifactId,
     * filtered by the likely vendors identified previously.
     * Returns up to 5 best matching product CPE entries sorted by similarity.
     * 
     * @param likelyVendors Set of vendor names to filter products by
     * @param artifactId Product artifact ID string to fuzzy match
     * @return List of best matching CPE entries for products
     * @throws SQLException on DB errors
     */
	public List<CpeEntryModel> searchForLikelyProducts(Set<String> likelyVendors, String artifactId)
			throws SQLException {
		 if (artifactId == null || artifactId.trim().isEmpty()) {
		        return Collections.emptyList();
		 }
		
		// List<CpeEntryModel> filteredCpes = new ArrayList<>();
		//Retrieve the CPE entries for filtered likely vendors from the CPE Dictionary database.
		List<CpeEntryModel> wrkEntries = entriesDao.getCpeEntriesForVendor(connection, likelyVendors);
		List<ScoredCpeEntryModel> scoredEntries = new ArrayList<>();
		//Iterate through CPE entries and match the product name with the artifact ID. Filter out the entries with threshold value greater than 0.7 and add it to scoredentries.
		for (CpeEntryModel entry : wrkEntries) {
			// Jaro-winkler similarity
			Double similarity = JWMatch(artifactId, entry.getProduct());
			if (similarity.compareTo(Double.valueOf(0.7d)) > 0) {
				scoredEntries.add(new ScoredCpeEntryModel(entry,similarity));
			}
		}
		
		 // Sort the scored entries by similarity in descending order and return the top 5 matches.
	    scoredEntries.sort((a, b) -> Double.compare(b.similarity, a.similarity));
		return scoredEntries.stream()
				.limit(5)
                .map(scored -> scored.entry)
                .collect(Collectors.toList());
	}
	
	 /**
     * Checks if a given package literal is a common package literal to be ignored
     * during vendor matching.
     * 
     * @param packageLiteral String literal to check
     * @return true if it is a common literal like "org" or "com", false otherwise
     */
	private boolean isCommonPackageLiteral(String packageLiteral) {
		for (String literal : COMMON_PACKAGE_LITERALS) {
			if (literal.equalsIgnoreCase(packageLiteral)) {
				return true;
			}
		}
		return false;
	}

	// Jaro-Winkler Similarity
	/**
     * Computes Jaro-Winkler similarity between two input strings.
     * 
     * @param input1 first input string
     * @param input2 second input string
     * @return similarity score between 0.0 and 1.0 (higher means more similar)
     */
	public double JWMatch(String input1, String input2) {
		JaroWinklerSimilarity jaroWinkler = new JaroWinklerSimilarity();
		double similarity = jaroWinkler.apply(input1, input2);
		return similarity;
	}
}