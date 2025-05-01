package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;

public class JarAnalyzer {
	private Log getLog() {
		return Engine.getMavenLog();
	}
	 public void scanJar(File jarFile) throws MojoExecutionException {
	        try (JarFile jar = new JarFile(jarFile)) {
	            // Get all entries in the JAR
	            Enumeration<JarEntry> entries = jar.entries();
	            
	            Set<String> packages = new HashSet<>();
	            
	            while (entries.hasMoreElements()) {
	                JarEntry entry = entries.nextElement();
	                if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
	                    // Extract package name from class path
	                    String className = entry.getName();
	                    int lastSlash = className.lastIndexOf('/');
	                    if (lastSlash > 0) {
	                        String packageName = className.substring(0, lastSlash).replace('/', '.');
	                        packages.add(packageName);
	                    }
	                }
	            }
	            
	            // Analyze packages for vendor evidence
	            analyzePackages(jarFile.getName(), packages);
	            analyzeManifest(jar);
	        } catch (IOException e) {
	            throw new MojoExecutionException("Failed to scan JAR: " + jarFile, e);
	        }
	    }
	    
	    private void analyzePackages(String jarName, Set<String> packages) {
	        // Common vendor package patterns (similar to Dependency-Check)
	        Map<String, String> vendorPatterns = new HashMap<>();
	        vendorPatterns.put("org\\.apache", "Apache");
	        vendorPatterns.put("com\\.google", "Google");
	        vendorPatterns.put("org\\.springframework", "Spring");
	        vendorPatterns.put("com\\.fasterxml", "Fasterxml");
	        vendorPatterns.put("org\\.eclipse", "Eclipse");
	        vendorPatterns.put("org\\.jetbrains", "JetBrains");
	        vendorPatterns.put("io\\.netty", "Netty");
	        vendorPatterns.put("org\\.slf4j", "SLF4J");
	        vendorPatterns.put("ch\\.qos\\.logback", "Logback");
	        vendorPatterns.put("org\\.junit", "JUnit");
	        
	        // Find matching patterns
	        Map<String, Integer> vendorCounts = new HashMap<>();
	        
	        for (String pkg : packages) {
	            for (Map.Entry<String, String> entry : vendorPatterns.entrySet()) {
	                if (pkg.matches(entry.getKey() + ".*")) {
	                    vendorCounts.merge(entry.getValue(), 1, Integer::sum);
	                }
	            }
	        }
	        
	        // Determine most likely vendor
	        if (!vendorCounts.isEmpty()) {
	            String mostLikelyVendor = Collections.max(vendorCounts.entrySet(), 
	                Map.Entry.comparingByValue()).getKey();
	            
	            getLog().info("JAR: " + jarName + " - Most likely vendor: " + mostLikelyVendor);
	        } else {
	            getLog().info("JAR: " + jarName + " - No vendor evidence found");
	        }
	    }
	    
	    private void analyzeManifest(JarFile jar) throws IOException {
	        Manifest manifest = jar.getManifest();
	        if (manifest != null) {
	            Attributes mainAttributes = manifest.getMainAttributes();
	            // Check common vendor attributes
	            String vendor = mainAttributes.getValue("Implementation-Vendor");
	            if (vendor == null) {
	                vendor = mainAttributes.getValue("Bundle-Vendor"); // OSGi
	            }
	            if (vendor != null) {
	                getLog().info("Found vendor in manifest: " + vendor);
	            }
	        }
	    }
}
