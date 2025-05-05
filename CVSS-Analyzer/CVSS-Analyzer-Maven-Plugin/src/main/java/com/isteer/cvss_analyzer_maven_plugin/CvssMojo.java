package com.isteer.cvss_analyzer_maven_plugin;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.model.DatabaseConfig;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.util.DbUtil;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.stream.Collectors;

/**
 * Goal which touches a timestamp file.
 */
@Mojo(name = "analyze-dependencies", defaultPhase = LifecyclePhase.COMPILE,requiresDependencyResolution = ResolutionScope.RUNTIME)
public class CvssMojo extends AbstractMojo {
	
	@Parameter(defaultValue = "${project}", required = true, readonly = true)
	private MavenProject project;
	
	@Parameter
	 private DatabaseConfig database; 

	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		   getLog().info("Starting CVSS analysis...");
		   
		   getLog().info("Getting database credentials from plugin configuration");
		   Engine.analysisMode=EngineMode.MAVEN_PLUGIN;
		   DbUtil.withDbCredentials(database.getUrl(), database.getUsername(), database.getPassword());
		    // 1. Get ALL dependencies (including transitive ones)
		    Set<Artifact> artifacts = project.getArtifacts();
		    
		    if (artifacts.isEmpty()) {
		        getLog().warn("No dependencies found in project!");
		        return;
		    }

		    // 2. Convert to DependencyModel list
		    List<DependencyModel> dependencies = artifacts.stream()
		        .map(artifact -> {
		            DependencyModel model = new DependencyModel();
		            model.setArtifact(artifact);
		            model.setDependencyName(
		                artifact.getGroupId() + ":" + 
		                artifact.getArtifactId() + ":" + 
		                artifact.getType()+":"+
		                artifact.getVersion()+":" +
		                artifact.getScope()
		            );
		            return model;
		        })
		        .collect(Collectors.toList());

		    getLog().info("Found " + dependencies.size() + " dependencies to analyze");

		    // 3. Run analysis
		    try {
		        new Engine()
		            .withDependencies(dependencies)
		            .withLog(getLog())  // Pass Maven's logger
		            .analyze(EngineMode.MAVEN_PLUGIN);
		        Engine.GenerateReport();
		        Engine.checkForVulnerabilityForDependencies();
		    } catch (Exception e) {
		        getLog().error("Analysis failed: " + e.getMessage(), e);
		        throw new MojoExecutionException("Analysis failed", e);
		    }
	}
}
