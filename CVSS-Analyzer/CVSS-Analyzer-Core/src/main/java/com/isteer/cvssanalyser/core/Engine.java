package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.util.HtmlReportGenerator;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;

public class Engine {
	static List<DependencyModel> dependencies;
	private Integer DEFAULT_VULNERABILITY_SCORE_THRESHOLD = 7;
	Logger logger = LoggerFactory.getLogger(Engine.class);
	private static Log mavenLog;
	public static EngineMode analysisMode;
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
			try {
				analyzeMavenPlugin();
			} catch (MojoExecutionException e) {
				e.printStackTrace();
			}
		}

	}
	public static Log getMavenLog() {
		return mavenLog;
	}
	private void analyzePom() {
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
			}else {
				System.out.println(dep.getDependencyName());
			}
		}
		Object result = cveClient.getAllVulnerabilities(cpenames);
	}
	
	private void analyzeMavenPlugin() throws MojoExecutionException {
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
		mavenLog.info("CPE names list size: "+cpenames.size());
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
