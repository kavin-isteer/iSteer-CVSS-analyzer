package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.maven.plugin.logging.Log;

import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityCvssMetricsModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityDetailsModel;
import com.isteer.cvssanalyser.core.util.HtmlReportGenerator;

public class Engine {
	public static List<DependencyModel> dependencies;
	
	private static Log mavenLog;
	
	public static EngineMode analysisMode;
	
	public static Double thresholdValue = 8.0;
	
	public static Log getMavenLog() {
		return mavenLog;
	}
	
	public Engine withDependencies(List<DependencyModel> dependencies) {
		Engine.dependencies=dependencies;
		return this;
	}
	public Engine withLog(Log logger) {
		Engine.mavenLog=logger;
		return this;
	}
	
	public void analyze(EngineMode analyzeMode) {
		Engine.analysisMode=analyzeMode;
		if(analyzeMode==EngineMode.POM) {
			analyzePom();
		}else if(analyzeMode==EngineMode.MAVEN_PLUGIN) {
			analyzeMavenPlugin();
		}

	}
	
	private void analyzePom() {
		GAVAnalyzer gavAnalyzer = new GAVAnalyzer();
		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		CveClient cveClient = new CveClient();
		
	    dependencies =  gavAnalyzer.fetchProjectDependenciesFromMavenTree();
	    gavAnalyzer.collectGAVEvidencesFromDependencyName(dependencies);
		normalizer.normalizeDependencyEvidences(dependencies);
		int dependencyCount = 0;
		for(DependencyModel dep:dependencies) {
			cveClient.fetchVulnerabilitiesForDependency(dep);
			dependencyCount++;
			if(dependencyCount % 25 == 0) {
				try {
					System.out.println("Fetched vulnerabilities for " + dependencyCount + " out of" + dependencies.size() + " dependencies");
					Thread.sleep(10000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
		for(DependencyModel dep:dependencies) {
			if(dep.getVulnerabilities().size()>0) {
				System.out.println("Found "+dep.getVulnerabilities().size()+" vulnerabilities for dependency:"+dep.getDependencyName());
			}else {
				System.out.println("No vulnerabilities found for dependency: "+ dep.getDependencyName());
			}
		}
	}
	
	private void analyzeMavenPlugin(){
		JarAnalyzer jarAnalyzer = new JarAnalyzer();
		GAVAnalyzer gavAnalyser = new GAVAnalyzer();
		CveClient cveClient = new CveClient();
		int dependencyCount = 0;
		gavAnalyser.collectGAVEvidencesFromDependencyName(dependencies);
		
		jarAnalyzer.collectEvidencesFromJar(dependencies);
		
		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		getMavenLog().info("Resolving evidences to CPE names.......");
		normalizer.normalizeDependencyEvidences(dependencies);
		getMavenLog().info("Fetching vulnerability details for the dependencies from the NVD api(This step requires Internet connection!!)");
		
		for(DependencyModel dep:dependencies) {
			if(dep.getCpeEnumeration()!=null) {
				dependencyCount++;
				cveClient.fetchVulnerabilitiesForDependency(dep);
			}
			if(dependencyCount % 25 == 0) {
				try {
					getMavenLog().info("Fetched vulnerabilities for " + dependencyCount + " out of " + dependencies.size() + " dependencies");
					Thread.sleep(10000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public static void GenerateReport() {
		getMavenLog().info("Generating dependencies vulnerability report....");
		File reportFile = new File("target/");
		HtmlReportGenerator reportGenerator = new HtmlReportGenerator();
		try {
			reportGenerator.generateReport(dependencies, reportFile);
		} catch (IOException e) {
			getMavenLog().error("Error occured during generating report");
			e.printStackTrace();
		}
	}
	public static void checkForVulnerabilityForDependencies() {
		System.out.println("inside the method");
		boolean isThresholdExceeded=false;
		for(DependencyModel dep:dependencies) {
			if(dep.getVulnerabilities().size()>0) {
				getMavenLog().error("Found "+dep.getVulnerabilities().size()+" vulnerabilities for dependency:"+dep.getDependencyName());
				for(VulnerabilityDetailsModel vulnerabilities : dep.getVulnerabilities()) {
					for(VulnerabilityCvssMetricsModel cvssMetrics : vulnerabilities.getCvssMetrics()) {
						if(cvssMetrics.getBaseScore()>=thresholdValue) {
							getMavenLog().error("Vulnerability found with CVSS score greater than threshold value: "+thresholdValue+"\n"+
							"Vulnerability ID: "+vulnerabilities.getCveId()+"\n"+
							"CVSS Score: "+cvssMetrics.getBaseScore()+"\n"+
							"CVSS Vector: "+cvssMetrics.getVectorString());
							isThresholdExceeded=true;
						}else {
							getMavenLog().error("Vulnerability found with CVSS score less than threshold value: "+thresholdValue+"\n"+
									"Vulnerability ID: "+vulnerabilities.getCveId()+"\n"+
									"CVSS Score: "+cvssMetrics.getBaseScore()+"\n"+
									"CVSS Vector: "+cvssMetrics.getVectorString());
						}
					}
				}
			}else {
			//	getMavenLog().info("No vulnerabilities found for dependency: "+ dep.getDependencyName());
			}
		}
		if(isThresholdExceeded) {
			throw new RuntimeException("One or more dependencies found with vulnerability with base score greater than threshold value: "+thresholdValue);
		}

	}
}
