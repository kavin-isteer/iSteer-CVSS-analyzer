package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.apache.commons.text.similarity.JaroWinklerSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;

import com.isteer.cvssanalyser.core.dao.CPEEntriesDao;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class FuzzySearchTool {
	public static Integer DISTANCE_THRESHOLD = 3;
	private DbUtil dbUtil = new DbUtil();
	private final Connection connection = dbUtil.getConnection();
	private CPEEntriesDao entriesDao = new CPEEntriesDao();
	private String[] COMMON_PACKAGE_LITERALS = { "org", "com" };

	public FuzzySearchTool withDistanceThreshold(Integer threshold) {
		FuzzySearchTool.DISTANCE_THRESHOLD = threshold;
		return this;
	}

	public boolean isMatch(String input1, String input2) {
		LevenshteinDistance distance = new LevenshteinDistance();
		int score = distance.apply(input1, input2);
		// Engine.logger.info("score is: "+score);
		if(input1.length()<input2.length()) {
			return false;
		}
		if((input1.length()==input2.length()) && score !=0) {
			return false;
		}
		/**
		 * if (input1.length()==input2.length()) { // Engine.logger.info("input1 and
		 * input2 length are equal"); if(score!=0) { // Engine.logger.info("Score is not
		 * zero returning false"); return false; } } if
		 * (input2.length()>input1.length()) { // Engine.logger.info("input1 and input2
		 * length are not equal"); int wrkLengthDiff = input2.length()-input1.length();
		 * int tempThreshold = wrkLengthDiff/2; // Engine.logger.info("tempThreshold is
		 * :"+tempThreshold); if(score<=tempThreshold) { return true; } }
		 **/

		if (score <= DISTANCE_THRESHOLD) {
			return true;
		}

		return false;
	}

	public int match(String input1, String input2) {
		LevenshteinDistance distance = new LevenshteinDistance();
		int score = distance.apply(input1, input2);
		return score;
	}

	public void searchForLikelyCpes(DependencyModel dependency) throws SQLException {
		// in line comments---
		Set<String> likelyVendors = new HashSet<>();
		for (Evidence ev : dependency.getVendorEvidences()) {
			if (ev.getEvidenceType() == EvidenceType.GROUP_ID) {
				likelyVendors = searchForLikelyVendors(ev.getEvidence());
			}
		}
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
				if(wrkCPELiterals.length>6) {
					wrkCpeNameModel.setUpdate(wrkCPELiterals[6]);
				}
				// Engine.getMavenLog().info("Adding likely CPE for dependency:
				// "+dependency.getDependencyName()+" - "+wrkCpeNameModel.getCPE23Uri());
				dependency.addLikelyCPEs(wrkCpeNameModel);
			}
			Engine.logger.info("Total likely CPEs found: " + filteredCpes.size());
		}
	}

	public Set<String> searchForLikelyVendors(String groupId) throws SQLException {
		if (groupId == null || groupId.equalsIgnoreCase("")) {
			return null;
		}
		String[] wrkGroupIdStrings = groupId.split("\\.");
		List<String> vendorNames = entriesDao.getDistinctVendorsList(connection);
		Set<String> likelyMatch = new HashSet<>();
		for (String literal : wrkGroupIdStrings) {
			if (isCommonPackageLiteral(literal)) {
				// Engine.logger.info("Is common package literal :"+literal);
				continue;
			}
			for (String vendor : vendorNames) {
				//LevenshteinDistance match
				/*
				 * if (isMatch(literal, vendor)) { likelyMatch.add(vendor); }
				 */
				
				//Jaro-winkler similarity
				Double similarity = JWMatch(literal, vendor);
				if(similarity.compareTo(Double.valueOf(0.9d))>0) {
					likelyMatch.add(vendor);
				}
			}
		}
		return likelyMatch;
	}

	public List<CpeEntryModel> searchForLikelyProducts(Set<String> likelyVendors, String artifactId)
			throws SQLException {
		if (artifactId == null || artifactId.equalsIgnoreCase("")) {
			return null;
		}
		//	List<CpeEntryModel> filteredCpes = new ArrayList<>();
		List<CpeEntryModel> wrkEntries = entriesDao.getCpeEntriesForVendor(connection, likelyVendors);
		CpeEntryModel bestMatch = null;
	    double highestSimilarity = 0.0;
		for (CpeEntryModel entry : wrkEntries) {
			//LevenshteinDistance match
			/*
			 * if (isMatch(artifactId, entry.getProduct())) { filteredCpes.add(entry); }
			 */
			
			//Jaro-winkler similarity
			Double similarity = JWMatch(artifactId, entry.getProduct());
			if(similarity.compareTo(Double.valueOf(0.9d))>0) {
				if (similarity > highestSimilarity) {
		            highestSimilarity = similarity;
		            bestMatch = entry;
		        }
			}
		}
		if(bestMatch==null) {
			return new ArrayList<>();
		}
		return Arrays.asList(bestMatch);
	}

	private boolean isCommonPackageLiteral(String packageLiteral) {
		for (String literal : COMMON_PACKAGE_LITERALS) {
			if (literal.equalsIgnoreCase(packageLiteral)) {
				return true;
			}
		}
		return false;
	}
	
	//Jaro-Winkler Similarity
		public double JWMatch(String input1,String input2) {
			JaroWinklerSimilarity jaroWinkler = new JaroWinklerSimilarity();
	        double similarity = jaroWinkler.apply(input1,input2);
	        return similarity;
		}
}
