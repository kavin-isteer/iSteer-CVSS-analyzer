package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.Arrays;
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

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;

import com.isteer.cvssanalyser.core.dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.DependencyHintModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class JarAnalyzer {
	private Log getLog() {
		return Engine.getMavenLog();
	}
	public void collectEvidencesFromJar(List<DependencyModel> dependencies) {
		getLog().info("Collecting evidences from Jar file packages and Manifest file");
		for(DependencyModel dependency:dependencies) {
			if(!dependency.getArtifact().getType().equals("jar")) {
				continue;
			}
			//getLog().info("Jar file: "+dependency.getArtifact().getFile().getName());
			//package vendor evidence
			Evidence packageVendorEvidence = collectVendorEvidenceFromPackage(dependency.getArtifact().getFile());
			if(packageVendorEvidence!=null) {
				dependency.addVendorEvidence(packageVendorEvidence);
			//	getLog().info("adding package vendor evidence: "+packageVendorEvidence);
			}
			
			//manifest vendor evidence
			List<Evidence> manifestVendorEvidence = collectVendorEvidencesFromManifest(dependency.getArtifact().getFile());
			if(manifestVendorEvidence!=null ) {
				for(Evidence wrkEvidence:manifestVendorEvidence) {
				dependency.addVendorEvidence(wrkEvidence);
			//	getLog().info("adding manifest vendor evidence: "+manifestVendorEvidence);
				}
			}
			
			//manifest product evidence
			Evidence manifestProductEvidence = collectProductEvidenceFromManifest(dependency.getArtifact().getFile());
			if(manifestProductEvidence!=null) {
				dependency.addProductEvidences(manifestProductEvidence);
			//	getLog().info("adding manifest product evidence: "+manifestProductEvidence);
			}
			
			//manifest version evidence
			Evidence manifestVersionEvidence = collectVersionEvidenceFromManifest(dependency.getArtifact().getFile());
			if(manifestVersionEvidence!=null) {
				dependency.addVersionEvidences(manifestVersionEvidence);
			//	getLog().info("adding manifest version evidence: "+manifestVersionEvidence);
			}
			
		}
	}
	public Evidence collectVendorEvidenceFromPackage(File jarFile){
		DependencyHintDao hintDao = new DependencyHintDao();
		DbUtil dbUtil = new DbUtil();
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
	            
	            List<DependencyHintModel> hints =  hintDao.getAllVendorDependencyHints(dbUtil.getConnection(), "package");
	            for(DependencyHintModel hint:hints) {
	            	for(String wrkPackage:packages) {
	            		if(wrkPackage.toLowerCase().startsWith(hint.getMatch_key().toLowerCase())) {
	            			Evidence evidence = new Evidence();
	            			evidence.setEvidence(wrkPackage);
	            			evidence.setEvidenceType(EvidenceType.PACKAGE_NAME);
	            			evidence.setResolvedValue(hint.getStandardized_name());
	            			return evidence;
	            		}
	            	}
	            }
	        } catch (IOException e) {
	            throw new RuntimeException("Failed to scan JAR: " + jarFile, e);
	        }
		  return null;
	}
	/**
	 * Collects vendor evidence from JAR manifest files
	 * @param jarFile The JAR file to analyze
	 * @return Evidence object with the best manifest match, or null if no match found
	 */
	public List<Evidence> collectVendorEvidencesFromManifest(File jarFile) {
	    DbUtil dbUtil = new DbUtil();
	    
	    try (JarFile jar = new JarFile(jarFile);
	         Connection connection = dbUtil.getConnection()) {
	        
	        // 1. Extract manifest attributes
	        Manifest manifest = jar.getManifest();
	        if (manifest == null) {
	            getLog().debug("No manifest found in JAR: " + jarFile.getName());
	            return null;
	        }


	        // 2. Check all potential vendor attributes
	        Attributes mainAttributes = manifest.getMainAttributes();
	        List<Evidence> bestEvidence = checkManifestVendorAttributes(mainAttributes);
	        
	        return bestEvidence;

	    } catch (Exception e) {
	    	throw new RuntimeException("Failed to analyze manifest in JAR: " + jarFile, e);
	    }
	}

	private List<Evidence> checkManifestVendorAttributes(Attributes attributes) {
	    // Ordered by priority of vendor attributes
	    String[] vendorAttributes = {
	        "Implementation-Vendor",
	        "Bundle-Vendor",
	        "Specification-Vendor",
	        "Created-By",
	        "Built-By"
	    };
	    List<Evidence> evidences = new ArrayList<>();
	    for (String attribute : vendorAttributes) {
	        String value = attributes.getValue(attribute);
	        if (value != null) {
	             Evidence evidence = new Evidence();
	             evidence.setEvidence(value);
	             evidence.setEvidenceType(EvidenceType.MANIFEST_ENTRY);
	             evidence.setEvidenceTitle(attribute);
	            evidences.add(evidence);
	        }
	    }
	    return evidences;
	}
	/**
	 * Collects product evidence from JAR manifest files
	 * @param jarFile The JAR file to analyze
	 * @return Evidence object with the best product match, or null if no match found
	 */
	public Evidence collectProductEvidenceFromManifest(File jarFile) {
	    DependencyHintDao hintDao = new DependencyHintDao();
	    DbUtil dbUtil = new DbUtil();
	    
	    try (JarFile jar = new JarFile(jarFile);
	         Connection connection = dbUtil.getConnection()) {
	        
	        // 1. Extract manifest if exists
	        Manifest manifest = jar.getManifest();
	        if (manifest == null) {
	            getLog().debug("No manifest found in JAR: " + jarFile.getName());
	            return null;
	        }

	        // 2. Get product hints from database (type='product' and evidence_type='manifest')
	        List<DependencyHintModel> hints = hintDao.getAllProductDependencyHints(connection, "manifest");
	        if (hints.isEmpty()) {
	            getLog().warn("No product hints found in database for manifest analysis");
	            return null;
	        }

	        // 3. Check manifest attributes for product info
	        Attributes mainAttributes = manifest.getMainAttributes();
	        Evidence bestEvidence = checkProductAttributes(mainAttributes, hints);

	        return bestEvidence;

	    } catch (Exception e) {
	        throw new RuntimeException("Failed to analyze manifest in JAR: " + jarFile, e);
	    }
	}

	private Evidence checkProductAttributes(Attributes attributes, List<DependencyHintModel> hints) {
	    // Ordered by priority of product attributes
	    String[] productAttributes = {
	        "Implementation-Title",
	        "Bundle-SymbolicName",  // OSGi
	        "Specification-Title",  // Java Spec
	        "Bundle-Name",          // OSGi
	        "Extension-Name",       // Legacy
	        "Short-Name"            // Sometimes used
	    };

	    for (String attribute : productAttributes) {
	        String value = attributes.getValue(attribute);
	        if (value != null && !value.trim().isEmpty()) {
	            // Find matching hint (case insensitive contains match)
	            for (DependencyHintModel hint : hints) {
	                if (value.toLowerCase().contains(hint.getMatch_key().toLowerCase())) {
	                    Evidence evidence = new Evidence();
	                    evidence.setEvidence(value);
	                    evidence.setEvidenceType(EvidenceType.MANIFEST_ENTRY);
	                    evidence.setResolvedValue(hint.getStandardized_name());
	                    return evidence;
	                }
	            }
	        }
	    }
	    return null;
	}
	/**
	 * Collects version evidence from JAR manifest files
	 * @param jarFile The JAR file to analyze
	 * @return Version evidence or null if no version found
	 */
	public Evidence collectVersionEvidenceFromManifest(File jarFile) {
	    try (JarFile jar = new JarFile(jarFile)) {
	        Manifest manifest = jar.getManifest();
	        if (manifest == null) {
	            getLog().debug("No manifest found in: " + jarFile.getName());
	            return null;
	        }

	        // Ordered by version attribute priority
	        String[] versionAttributes = {
	            "Implementation-Version",  // Highest priority
	            "Bundle-Version",          // OSGi
	            "Specification-Version",   // Java Spec
	            "Version",                 // Generic
	            "Build-Version"            // Alternative
	        };

	        Attributes mainAttrs = manifest.getMainAttributes();
	        for (String attr : versionAttributes) {
	            String version = mainAttrs.getValue(attr);
	            if (version != null && !version.trim().isEmpty()) {
	                Evidence evidence = new Evidence();
	                evidence.setEvidence(version);
	                evidence.setEvidenceType(EvidenceType.MANIFEST_ENTRY);
	                evidence.setResolvedValue(normalizeVersion(version));
	                return evidence;
	            }
	        }
	        return null;

	    } catch (IOException e) {
	        throw new RuntimeException("Failed to read JAR: " + jarFile, e);
	    }
	}

	private String normalizeVersion(String version) {
	    // Remove leading/trailing quotes and whitespace
	    String normalized = version.trim()
	        .replaceAll("^[\"']|[\"']$", "")
	        .replaceAll("-(RELEASE|FINAL|GA)", "");  // Common version suffixes
	    
	    // Handle OSGi qualifiers
	    if (normalized.contains(".")) {
	        String[] parts = normalized.split("\\.");
	        if (parts.length > 3) {  // Trim qualifiers like 1.2.3.RELEASE -> 1.2.3
	            normalized = String.join(".", Arrays.copyOfRange(parts, 0, 3));
	        }
	    }
	    
	    return normalized;
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
