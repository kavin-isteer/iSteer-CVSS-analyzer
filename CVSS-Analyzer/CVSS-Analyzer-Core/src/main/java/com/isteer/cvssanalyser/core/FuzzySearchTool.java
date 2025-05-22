package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.text.similarity.LevenshteinDistance;

import com.isteer.cvssanalyser.core.dao.CPEEntriesDao;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class FuzzySearchTool {
	public static Integer DISTANCE_THRESHOLD=3;
	private DbUtil dbUtil = new DbUtil();
	private final Connection connection = dbUtil.getConnection();
	private CPEEntriesDao entriesDao = new CPEEntriesDao();
	
	public FuzzySearchTool withDistanceThreshold(Integer threshold) {
		FuzzySearchTool.DISTANCE_THRESHOLD=threshold;
		return this;
	}
	
	public boolean isMatch(String input1, String input2) {
	//Engine.getMavenLog().info("Matching words "+input1+" and "+input2);
		LevenshteinDistance distance = new LevenshteinDistance();
		int score = distance.apply(input1, input2);
	//	Engine.getMavenLog().info("Match score is :"+String.valueOf(score));
		if(score<=DISTANCE_THRESHOLD) {
			return true;
		}
		return false;
	}
	public void searchForLikelyCpes(DependencyModel dependency) throws SQLException {
		List<String> likelyVendors = new ArrayList<>();
		for(Evidence ev:dependency.getVendorEvidences()) {
			if(ev.getEvidenceType()==EvidenceType.GROUP_ID) {
				likelyVendors = searchForLikelyVendors(ev.getEvidence());			
			}
		}
		if(likelyVendors.size()==0) {
			Engine.getMavenLog().info("Unable to find vendor through fuzzy search for dependency: "+dependency.getDependencyName());
			return;
		}
		List<CpeEntryModel> filteredCpes=new ArrayList<>();
		for(Evidence ev:dependency.getProductEvidences()) {
			if(ev.getEvidenceType()==EvidenceType.ARTIFACT_ID) {
				filteredCpes = searchForLikelyProducts(likelyVendors, ev.getEvidence());
			}
		}
		if(filteredCpes.size()>0) {
			for(CpeEntryModel entry:filteredCpes) {
				CPENameModel wrkCpeNameModel = new CPENameModel();
				wrkCpeNameModel.setProduct(entry.getProduct());
				wrkCpeNameModel.setVendor(entry.getVendor());
				wrkCpeNameModel.setVersion(entry.getVersion());
				wrkCpeNameModel.setValidCpe(true);
			//	Engine.getMavenLog().info("Adding likely CPE for dependency: "+dependency.getDependencyName()+" - "+wrkCpeNameModel.getCPE23Uri());
				dependency.addLikelyCPEs(wrkCpeNameModel);
			}
			
		}
	}
	public List<String> searchForLikelyVendors(String groupId) throws SQLException{
		if(groupId==null || groupId.equalsIgnoreCase("")) {
			return null;
		}
		String[] wrkGroupIdStrings = groupId.split("\\.");
		//Engine.getMavenLog().info("Group id is: "+groupId+" size of split array is : "+wrkGroupIdStrings.length);
		List<String> vendorNames = entriesDao.getDistinctVendorsList(connection);
		//Engine.getMavenLog().info("Distinct vendor size is:"+vendorNames.size());
		List<String> likelyMatch = new ArrayList<>();
		for(String literal:wrkGroupIdStrings) {
		//	Engine.getMavenLog().info("Group Id literal is: "+literal);
			for(String vendor:vendorNames) {
		//		Engine.getMavenLog().info("Current vendor name is :"+vendor);
				if(isMatch(literal,vendor)) {
					if(vendor.length()>=literal.length()) {
						likelyMatch.add(vendor);
					}
				}
			}
		}
		return likelyMatch;
	}
	public List<CpeEntryModel> searchForLikelyProducts(List<String> likelyVendors, String artifactId) throws SQLException{
		if(artifactId==null || artifactId.equalsIgnoreCase("")) {
			return null;
		}
		List<CpeEntryModel> filteredCpes = new ArrayList<>();
		List<CpeEntryModel> wrkEntries = entriesDao.getCpeEntriesForVendor(connection, likelyVendors);
		for(CpeEntryModel entry:wrkEntries) {
			if(isMatch(artifactId, entry.getProduct())) {
				filteredCpes.add(entry);
			}
		}
		return filteredCpes;
	}
}
