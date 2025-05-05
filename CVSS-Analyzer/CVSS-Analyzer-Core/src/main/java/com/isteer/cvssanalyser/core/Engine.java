package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.maven.plugin.logging.Log;

import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.util.HtmlReportGenerator;

public class Engine {
	static List<DependencyModel> dependencies;
	
	private static Log mavenLog;
	
	public static EngineMode analysisMode;
	
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
		
		for(DependencyModel dep:dependencies) {
			cveClient.fetchVulnerabilitiesForDependency(dep);
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
		
		gavAnalyser.collectGAVEvidencesFromDependencyName(dependencies);
		
		jarAnalyzer.collectEvidencesFromJar(dependencies);
		
		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		normalizer.normalizeDependencyEvidences(dependencies);
		
		List<String> cpenames = new ArrayList<>();
		List<String> notfoundDepName = new ArrayList<>();
		
		for(DependencyModel dep:dependencies) {
			if(dep.getCpeEnumeration()!=null) {
				cpenames.add(dep.getCpeEnumeration().getCPE23Uri());
			}else {
				notfoundDepName.add(dep.getDependencyName());
			}
		}
		
		/*
		 * for(DependencyModel dep : dependencies) {
		 * mavenLog.info(dep.getDependencyName());
		 * if(dep.getArtifact().getType().equals("jar")) {
		 * jarAnalyzer.scanJar(dep.getArtifact().getFile()); } }
		 */
		
		mavenLog.info("Dependencies size is :" +Engine.dependencies.size());
		mavenLog.info("----------------------------------------Resolved CPE names-----------------------------------------");
		mavenLog.info("CPE names list size: "+ cpenames.size());
		for(String s:cpenames) {
			mavenLog.info(s);
		}
		for(String s:notfoundDepName) {
			mavenLog.info(s);
		}
	}
	
	public static void GenerateReport() {
		getMavenLog().info("Generating Report....");
		File reportFile = new File("target/");
		HtmlReportGenerator reportGenerator = new HtmlReportGenerator();
		try {
			reportGenerator.generateReport(dependencies, reportFile);
		} catch (IOException e) {
			getMavenLog().error("Error occured during generating report");
			e.printStackTrace();
		}
	}
}
