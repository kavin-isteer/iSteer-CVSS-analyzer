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
import com.isteer.cvssanalyser.core.lucene.LuceneCpeSearcher;
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

	private LuceneCpeSearcher luceneSearcher = new LuceneCpeSearcher();

	private static boolean USE_LUCENE_INDEX = false; // Use lucene by default

	private static boolean LUCENE_ALL_FIELD_SEARCH = true; // Use lucene by default

	public static void useLucene(boolean useLucene) {
		USE_LUCENE_INDEX = useLucene;
	}

	/**
	 * Given a DependencyModel, attempts to find likely matching CPE entries based
	 * on vendor and product evidences extracted from the dependency.
	 * 
	 * @param dependency DependencyModel to search likely CPEs for
	 * @throws Exception
	 */
	public void searchForLikelyCpes(DependencyModel dependency) {
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		Engine.logger.debug("Using lucene index searcher!!");
		Engine.logger.debug("Using lucene all field searcher!!");
		List<String> vendorSearchStrings = new ArrayList<>();
		List<String> productSearchStrings = new ArrayList<>();
		List<String> versionSearchStrings = new ArrayList<>();

		for (Evidence ev : dependency.getVendorEvidences()) {
			if (ev.getEvidenceType() == EvidenceType.GROUP_ID) {
				String[] wrkGroupIdStrings = ev.getEvidence().split("\\.");
				for (String wrkStr : wrkGroupIdStrings) {
					if (!isCommonPackageLiteral(wrkStr)) {
						vendorSearchStrings.add(wrkStr);
					}
				}
			} else if (ev.getEvidenceType() == EvidenceType.MANIFEST_ENTRY) {

			} else {
				vendorSearchStrings.add(ev.getEvidence());
			}
		}

		for (Evidence ev : dependency.getProductEvidences()) {
			if (ev.getEvidenceType() == EvidenceType.MANIFEST_ENTRY) {

			} else {
				productSearchStrings.add(ev.getEvidence());
			}
		}
		for (Evidence ev : dependency.getVersionEvidences()) {
			if (ev.getEvidenceType() == EvidenceType.MANIFEST_ENTRY) {

			} else {
				versionSearchStrings.add(ev.getEvidence());
			}
		}
		List<CPENameModel> likelyCpeNames = searchForLikelyCpeName(vendorSearchStrings, productSearchStrings, versionSearchStrings);
		if (likelyCpeNames.size() > 0) {
			for (CPENameModel cpeName : likelyCpeNames) {
				dependency.addLikelyCPEs(cpeName);
			}
		}
//		try {
//		filteredCpes = luceneSearcher.multiFieldSearch(vendorSearchStrings, productSearchStrings, versionSearchStrings);
//		}catch (Exception e) {
//			Engine.logger.debug(e.getMessage());
//			Engine.logger.debug("Exception occured while searching for likely cpes !!");
//		}
//		// Create CPE entry model for each filtered CPE
//		if (filteredCpes.size() > 0) {
//			for (CpeEntryModel entry : filteredCpes) {
//				CPENameModel wrkCpeNameModel = new CPENameModel();
//				wrkCpeNameModel.setProduct(entry.getProduct());
//				wrkCpeNameModel.setVendor(entry.getVendor());
//				wrkCpeNameModel.setVersion(entry.getVersion());
//				wrkCpeNameModel.setValidCpe(true);
//				String[] wrkCPELiterals = entry.getCpeName().split(":");
//				if (wrkCPELiterals.length > 6) {
//					wrkCpeNameModel.setUpdate(wrkCPELiterals[6]);
//				}
//				// Engine.getMavenLog().info("Adding likely CPE for dependency:
//				// "+dependency.getDependencyName()+" - "+wrkCpeNameModel.getCPE23Uri());
//				dependency.addLikelyCPEs(wrkCpeNameModel);
//			}
//			Engine.logger.debug("Total likely CPEs found: " + filteredCpes.size());
//		}
	}
	
	public List<CPENameModel> searchForLikelyCpeName(List<String> vendorSearchStrings, List<String> productSearchStrings, List<String> versionSearchStrings) {
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		List<CPENameModel> likelyCpeNames = new ArrayList<>();
		try {
			filteredCpes = luceneSearcher.multiFieldSearch(vendorSearchStrings, productSearchStrings, versionSearchStrings);
			Engine.logger.info("Found likely cpes: "+filteredCpes.size());
		}catch (Exception e) {
			Engine.logger.debug(e.getMessage());
			Engine.logger.debug("Exception occured while searching for likely cpes !!");
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
				likelyCpeNames.add(wrkCpeNameModel);
			}
			Engine.logger.debug("Total likely CPEs found: " + filteredCpes.size());
		}
		return likelyCpeNames;
	}
	
	public List<CPENameModel> searchForLikelyCpeName(String vendorSearchString, String productSearchString) {
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		List<CPENameModel> likelyCpeNames = new ArrayList<>();
		try {
			filteredCpes = luceneSearcher.multiFieldSearch(vendorSearchString, productSearchString);
			Engine.logger.info("Found likely cpes: "+filteredCpes.size());
		}catch (Exception e) {
			Engine.logger.debug(e.getMessage());
			Engine.logger.debug("Exception occured while searching for likely cpes !!");
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
				likelyCpeNames.add(wrkCpeNameModel);
			}
			Engine.logger.debug("Total likely CPEs found: " + filteredCpes.size());
		}
		return likelyCpeNames;
	}
	
	public List<CPENameModel> searchForLikelyCpeName(String vendorSearchString, String productSearchString, String versionSearchString) {
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		List<CPENameModel> likelyCpeNames = new ArrayList<>();
		try {
			filteredCpes = luceneSearcher.multiFieldSearch(vendorSearchString, productSearchString, versionSearchString);
			Engine.logger.info("Found likely cpes: "+filteredCpes.size());
		}catch (Exception e) {
			Engine.logger.debug(e.getMessage());
			Engine.logger.debug("Exception occured while searching for likely cpes !!");
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
				likelyCpeNames.add(wrkCpeNameModel);
			}
			Engine.logger.debug("Total likely CPEs found: " + filteredCpes.size());
		}
		return likelyCpeNames;
	}
	
	public List<CPENameModel> searchForLikelyCpeName(List<String> vendorSearchString, List<String> productSearchString) {
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		List<CPENameModel> likelyCpeNames = new ArrayList<>();
		try {
			filteredCpes = luceneSearcher.multiFieldSearch(vendorSearchString, productSearchString);
			Engine.logger.info("Found likely cpes: "+filteredCpes.size());
		}catch (Exception e) {
			Engine.logger.debug(e.getMessage());
			Engine.logger.debug("Exception occured while searching for likely cpes !!");
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
				likelyCpeNames.add(wrkCpeNameModel);
			}
			Engine.logger.debug("Total likely CPEs found: " + filteredCpes.size());
		}
		return likelyCpeNames;
	}

	@Deprecated
	public void searchForLikelyCpesDeprecated(DependencyModel dependency) {
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		Set<String> likelyVendors = new HashSet<>();
		// filter out likely vendors from the list of vendor evidences
		try {
			likelyVendors = searchForLikelyVendors(dependency.getVendorEvidences());
		} catch (SQLException e) {
			e.printStackTrace();
		}
		if (likelyVendors.size() == 0) {
			// Engine.logger.info(
			// "Unable to find vendor through fuzzy search for dependency: " +
			// dependency.getDependencyName());
			return;
		}
		for (Evidence ev : dependency.getProductEvidences()) {
			if (ev.getEvidenceType() == EvidenceType.ARTIFACT_ID) {
				// Search for CPE entries with likely product from the filtered likely vendors
				// list
				try {
					filteredCpes = searchForLikelyProducts(likelyVendors, ev.getEvidence());
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		// Create CPE entry model for each filtered CPE
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
			Engine.logger.debug("Total likely CPEs found: " + filteredCpes.size());
		}
	}

	/**
	 * Searches for likely matching vendors based on evidence strings, primarily the
	 * groupId from Maven coordinates.
	 * 
	 * @param evidences List of Evidence objects related to vendor info
	 * @return Set of likely matching vendor names
	 * @throws SQLException on DB errors
	 */
	public Set<String> searchForLikelyVendors(List<Evidence> evidences) throws SQLException {
		Set<String> likelyMatch = new HashSet<>();
		// Retrieve the group Id evidence from the list of evidences.
		String groupId = "";
		for (Evidence ev : evidences) {
			if (ev.getEvidenceType() == EvidenceType.GROUP_ID) {
				groupId = ev.getEvidence();
			}
		}
		if (groupId != null && !groupId.equalsIgnoreCase("")) {

			// split the group id with dot as the delimiter.
			String[] wrkGroupIdStrings = groupId.split("\\.");
			if (vendorNames.size() == 0) {
				// Engine.logger.info("Hititng db for distinct vendor names");
				// Retrieve list of distinct vendor names from the CPE dictionary database.
				vendorNames = entriesDao.getDistinctVendorsList(connection);
			}

			for (String literal : wrkGroupIdStrings) {
				// If the literal is a common package name ignore it.
				if (isCommonPackageLiteral(literal)) {
					// Engine.logger.info("Is common package literal :"+literal);
					continue;
				}
				for (String vendor : vendorNames) {
					// Jaro-winkler similarity
					// If the literal matches with any of the vendor names from the CPE dictionary,
					// add that to likely match.
					Double similarity = JWMatch(literal, vendor);
					if (similarity.compareTo(Double.valueOf(0.9d)) > 0) {
						likelyMatch.add(vendor);
					}
				}
			}
		}
		// If vendor likely match not found with Group Artifact Verison info then
		// iterate through other evidences and search for likely matches.
		if (likelyMatch.size() == 0) {
			Engine.logger.debug("Vendor likely match not found. Searching with other evidences");
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
		Engine.logger
				.debug("Total Vendor likely match found after searching with other evidences: " + likelyMatch.size());
		return likelyMatch;
	}

	/**
	 * Searches for likely matching products for the given artifactId, filtered by
	 * the likely vendors identified previously. Returns up to 5 best matching
	 * product CPE entries sorted by similarity.
	 * 
	 * @param likelyVendors Set of vendor names to filter products by
	 * @param artifactId    Product artifact ID string to fuzzy match
	 * @return List of best matching CPE entries for products
	 * @throws SQLException on DB errors
	 */
	public List<CpeEntryModel> searchForLikelyProducts(Set<String> likelyVendors, String artifactId)
			throws SQLException {
		if (artifactId == null || artifactId.trim().isEmpty()) {
			return Collections.emptyList();
		}

		// List<CpeEntryModel> filteredCpes = new ArrayList<>();
		// Retrieve the CPE entries for filtered likely vendors from the CPE Dictionary
		// database.
		List<CpeEntryModel> wrkEntries = entriesDao.getCpeEntriesForVendor(connection, likelyVendors);
		List<ScoredCpeEntryModel> scoredEntries = new ArrayList<>();
		// Iterate through CPE entries and match the product name with the artifact ID.
		// Filter out the entries with threshold value greater than 0.7 and add it to
		// scoredentries.
		for (CpeEntryModel entry : wrkEntries) {
			// Jaro-winkler similarity
			Double similarity = JWMatch(artifactId, entry.getProduct());
			if (similarity.compareTo(Double.valueOf(0.7d)) > 0) {
				scoredEntries.add(new ScoredCpeEntryModel(entry, similarity));
			}
		}

		// Sort the scored entries by similarity in descending order and return the top
		// 5 matches.
		scoredEntries.sort((a, b) -> Double.compare(b.similarity, a.similarity));
		return scoredEntries.stream().limit(5).map(scored -> scored.entry).collect(Collectors.toList());
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

	public String normalizeNames(String name) {
		// This method will normalize the product name by removing special characters
		// and
		// converting it to lowercase.
		if (name == null || name.isEmpty()) {
			return null;
		}
		return name.replaceAll("\\s*\\([^)]*\\)", "").replaceAll("[^a-zA-Z0-9\\s]", "").toLowerCase().trim();
	}
}