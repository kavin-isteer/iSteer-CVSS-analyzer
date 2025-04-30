package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;

import com.isteer.cvssanalyser.core.Dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.DependencyHintModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.model.GAVModel;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class GAVAnalyzer {
	public static void main(String[] args) {
		GAVAnalyzer analyzer = new GAVAnalyzer();
		
		
	}
	
	public List<DependencyModel> fetchProjectDependenciesFromMavenTree() {
		DependencyTreeResolver treeResolver = new DependencyTreeResolver();
		File projectDir = new File(".");
		List<String> gavs = new ArrayList<>();
		List<DependencyModel> projectDependencies = new ArrayList<>();
		try {
			gavs = treeResolver.fetchDependencies(projectDir);
		} catch (IOException | InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		List<GAVModel> gavModels = new ArrayList<>();
		for (String gav : gavs) {
			String[] wrkMavenDependency = gav.split(":");
			GAVModel model = new GAVModel();
			DependencyModel dependency = new DependencyModel();
			//Dependency name
			dependency.setDependencyName(gav);
			if (wrkMavenDependency.length == 5) {
				//Group Id
				Evidence groupIdevidence = new Evidence();
				groupIdevidence.setEvidence(wrkMavenDependency[0]);
				groupIdevidence.setEvidenceType(EvidenceType.GROUP_ID);
				dependency.addVendorEvidence(groupIdevidence);
				//model.setGroupId(wrkMavenDependency[0]);
				//Artifact Id
				Evidence artifactIdevidence = new Evidence();
				artifactIdevidence.setEvidence(wrkMavenDependency[1]);
				artifactIdevidence.setEvidenceType(EvidenceType.ARTIFACT_ID);
				dependency.addProductEvidences(artifactIdevidence);
				//model.setArtifactId(wrkMavenDependency[1]);
				//Version
				Evidence versionIdevidence = new Evidence();
				versionIdevidence.setEvidence(wrkMavenDependency[3]);
				versionIdevidence.setEvidenceType(EvidenceType.VERSION);
				dependency.addVersionEvidences(versionIdevidence);
				
				projectDependencies.add(dependency);
				//model.setVersion(wrkMavenDependency[3]);
			} else if (wrkMavenDependency.length == 6) {
				//model.setGroupId(wrkMavenDependency[0]);
				//Group Id
				Evidence groupIdevidence = new Evidence();
				groupIdevidence.setEvidence(wrkMavenDependency[0]);
				groupIdevidence.setEvidenceType(EvidenceType.GROUP_ID);
				dependency.addVendorEvidence(groupIdevidence);
				//model.setArtifactId(wrkMavenDependency[1]);
				//Artifact Id
				Evidence artifactIdevidence = new Evidence();
				artifactIdevidence.setEvidence(wrkMavenDependency[1]);
				artifactIdevidence.setEvidenceType(EvidenceType.ARTIFACT_ID);
				dependency.addProductEvidences(artifactIdevidence);
				//model.setVersion(wrkMavenDependency[4]);
				//Version
				Evidence versionIdevidence = new Evidence();
				versionIdevidence.setEvidence(wrkMavenDependency[4]);
				versionIdevidence.setEvidenceType(EvidenceType.VERSION);
				dependency.addVersionEvidences(versionIdevidence);
				projectDependencies.add(dependency);
			}
		}
		return projectDependencies;
	}
	
	public List<CPENameModel> resolveGavsToCPENames(List<GAVModel> gavs){
		List<CPENameModel> cpesList = new ArrayList<>();
		if(gavs.size()<=0) {
			return cpesList;
		}
		DbUtil dbUtil = new DbUtil();
		Connection con = dbUtil.getConnection();
		DependencyHintDao dependencyHintDao = new DependencyHintDao();
		List<DependencyHintModel> hints = dependencyHintDao.getAllVendorDependencyHints(con);
		for(GAVModel gav:gavs) {
			CPENameModel cpeModel = new CPENameModel();
			for(DependencyHintModel hint:hints) {
				if(gav.getGroupId().toLowerCase().startsWith(hint.getMatch_key().toLowerCase())) {
					cpeModel.setVendor(hint.getStandardized_name());
				}
			}
			String wrkProductName = gav.getArtifactId().toLowerCase();
			wrkProductName = wrkProductName.replaceAll("[^a-z0-9_-]", "_");
			wrkProductName = wrkProductName.replace("-", "_");
			cpeModel.setProduct(wrkProductName);
			cpeModel.setVersion(gav.getVersion());
			cpesList.add(cpeModel);
		}
		return cpesList;
	}
	
	
}
