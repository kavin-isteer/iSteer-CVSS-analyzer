package com.isteer.cvssanalyser.core;

import java.util.ArrayList;
import java.util.List;

import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.model.DependencyModel;

public class Engine {
	List<DependencyModel> dependencies;
	public void analyze() {
		GAVAnalyzer gavAnalyzer = new GAVAnalyzer();
		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		CveClient cveClient = new CveClient();
	    dependencies =  gavAnalyzer.fetchProjectDependenciesFromMavenTree();
		normalizer.normalizeDependencyEvidences(dependencies);
		//To-Do fetch vulnerabilities and put it in dependencies
		List<String> cpenames = new ArrayList<>();
		for(DependencyModel dep:dependencies) {
			if(dep.getCpeEnumeration()!=null) {
				cpenames.add(dep.getCpeEnumeration().getCPE23Uri());
			}
		}
		Object result = cveClient.getAllVulnerabilities(cpenames);
	}
}
