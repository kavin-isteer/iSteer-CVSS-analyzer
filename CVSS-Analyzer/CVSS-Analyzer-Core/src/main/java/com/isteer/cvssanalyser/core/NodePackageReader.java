package com.isteer.cvssanalyser.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONObject;

import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;

public class NodePackageReader {
	private final Set<DependencyModel> allDependencies = new LinkedHashSet<>();

	public List<DependencyModel> analyze(String packageJson, String packageLockJson) throws IOException {

		if (packageLockJson != null && !packageLockJson.isEmpty()) {
			analyzePackageLockJson(packageLockJson);
		} else if (packageJson != null && !packageJson.isEmpty()) {
			analyzePackageJson(packageJson);
		}
		return new ArrayList<>(allDependencies);
	}

	private void analyzePackageJson(String  packageJson) throws IOException {
		System.out.println("Analysing package.json");
		String content = packageJson;
		JSONObject json = new JSONObject(content);

		String name = json.optString("name", "unknown");
		String version = json.optString("version", "unknown");
		String vendor = inferVendor(json, name);

		allDependencies.add(createDependency(name,vendor, refineProductName(name), refineVersion(version),"Package.Json"));
		extractDependenciesFromSection(json, "dependencies", "Package.Json");
		extractDependenciesFromSection(json, "devDependencies", "Package.Json");
		extractDependenciesFromSection(json, "optionalDependencies", "Package.Json");
		extractDependenciesFromSection(json, "peerDependencies", "Package.Json");
	}

	private void extractDependenciesFromSection(JSONObject json, String sectionName, String source) {
		System.out.println("Extracting dependencies from section: " + sectionName);
		if (json.has(sectionName)) {
			JSONObject deps = json.getJSONObject(sectionName);
			for (String depName : deps.keySet()) {
				String depVersion = deps.optString(depName, "unknown");
				String depVendor = extractVendorFromScopedName(depName);
				allDependencies.add(createDependency (depName, depVendor, refineProductName(depName), refineVersion(depVersion), source));
			}
		}
	}

	private void analyzePackageLockJson(String packageLockJson) throws IOException {
		System.out.println("Analysing package-lock.json");
		String content = packageLockJson;
		JSONObject json = new JSONObject(content);

		int lockfileVersion = json.optInt("lockfileVersion", 1);

		if (lockfileVersion >= 2 && json.has("packages")) {
			System.out.println("Lockfile version greater than 2 found");
			JSONObject packages = json.getJSONObject("packages");
			for (String path : packages.keySet()) {

				if (!path.equals(""))
					continue; // skip other than root package. Remove this condition to extract all node modules dependencies also.
				
				// System.out.println("package:" + path);
				JSONObject pkg = packages.getJSONObject(path);
				// System.out.println(pkg);
				if (!path.equals("")) {
					String version = pkg.optString("version", "unknown");
					String name = extractNameFromPath(path);
					if (name == null)
						continue;

					String vendor = extractVendorFromScopedName(name);
					allDependencies.add(createDependency(name, vendor, refineProductName(name), refineVersion(version),"Package-Lock.Json"));
				}
				if (path.equals("")) {
					extractDependenciesFromSection(pkg, "dependencies", "Package-Lock.Json");
					extractDependenciesFromSection(pkg, "devDependencies", "Package-Lock.Json");
					extractDependenciesFromSection(pkg, "optionalDependencies", "Package-Lock.Json");
					extractDependenciesFromSection(pkg, "peerDependencies", "Package-Lock.Json");
				}
			}
		} else if (json.has("dependencies")) {
			System.out.println("Lockfile version less than 2 found. Doing legacy analysis");
			JSONObject deps = json.getJSONObject("dependencies");
			extractNestedDependenciesLegacy("", deps);
		} else {
			System.out.println("lockfileVersion not found!!");
		}

		System.out.println("Completed package-lock.json analysis");
	}

	private void extractNestedDependenciesLegacy(String parent, JSONObject deps) {
		for (String name : deps.keySet()) {
			JSONObject entry = deps.getJSONObject(name);
			String version = entry.optString("version", "unknown");
			String vendor = extractVendorFromScopedName(name);

			allDependencies.add(createDependency(name, vendor, refineProductName(name), refineVersion(version), "Package-Lock.Json"));

			/*
			 * if (entry.has("dependencies")) { extractNestedDependenciesLegacy(name,
			 * entry.getJSONObject("dependencies")); }
			 */
		}
	}

	private String extractNameFromPath(String path) {
		if (path == null || path.isEmpty())
			return null;
		if (path.startsWith("node_modules/")) {
			String name = path.substring("node_modules/".length());
			if (name.startsWith("@")) {
				int secondSlash = name.indexOf("/", name.indexOf("/") + 1);
				return secondSlash != -1 ? name.substring(0, secondSlash) : name;
			} else {
				return name.contains("/") ? name.split("/")[0] : name;
			}
		}
		return null;
	}

	private String inferVendor(JSONObject json, String name) {
		String resolvedVendor="";
		if (json.has("author")) {
			Object author = json.get("author");
			if (author instanceof JSONObject) {
				resolvedVendor= ((JSONObject) author).optString("name", "unknown");
			} else if (author instanceof String) {
				resolvedVendor= (String) author;
			}
		}

		if (json.has("repository")) {
			JSONObject repo = json.optJSONObject("repository");
			if (repo != null) {
				String url = repo.optString("url", "");
				resolvedVendor= extractGitHubOrg(url);
			}
		}

		resolvedVendor= extractVendorFromScopedName(name);
		resolvedVendor = resolvedVendor.replace(' ', '_');
		return resolvedVendor;
	}

	private String extractVendorFromScopedName(String name) {
		if (name.startsWith("@") && name.contains("/")) {
			return name.substring(1, name.indexOf("/"));
		}
		return "unknown";
	}
	
	private String refineProductName(String scopedProductName) {
		if (scopedProductName.startsWith("@") && scopedProductName.contains("/")) {
			return scopedProductName.substring(scopedProductName.indexOf("/")+1);
		}
		return scopedProductName;
	}
	
	private String refineVersion(String rawVersion) {
		 if (rawVersion == null || rawVersion.trim().isEmpty()) {
	            return "";
	        }

	        // Remove common leading symbols used in semantic versioning
	        String cleaned = rawVersion.trim();

	        // Strip prefixes like ^, ~, >=, <=, =, >, <, v
	        cleaned = cleaned.replaceAll("^[\\^~><=v]+", "");

	        return cleaned;
	}
	
	private String extractGitHubOrg(String url) {
		if (url.contains("github.com")) {
			String[] parts = url.split("github.com[/:]");
			if (parts.length > 1) {
				String path = parts[1].replace(".git", "");
				return path.split("/")[0];
			}
		}
		return "";
	}
	private DependencyModel createDependency(String dependencyName, String vendor, String product, String version, String evidenceSource) {
		DependencyModel dependency = new DependencyModel();
		dependency.setDependencyName(dependencyName);
		//Add vendor evidence
		Evidence vendorEvidence = new Evidence();
		vendorEvidence.setEvidence(vendor);
		vendorEvidence.setEvidenceTitle(evidenceSource);
		vendorEvidence.setEvidenceType(EvidenceType.NODE_PACKAGE);
		vendorEvidence.setResolvedValue(vendor);
		dependency.addVendorEvidence(vendorEvidence);
		//Add product evidence
		Evidence productEvidence = new Evidence();
		productEvidence.setEvidence(product);
		productEvidence.setEvidenceTitle(evidenceSource);
		productEvidence.setEvidenceType(EvidenceType.NODE_PACKAGE);
		productEvidence.setResolvedValue(product);
		dependency.addProductEvidences(productEvidence);
		//Add version evidence
		Evidence versionEvidence = new Evidence();
		versionEvidence.setEvidence(version);
		versionEvidence.setEvidenceTitle(evidenceSource);
		versionEvidence.setEvidenceType(EvidenceType.NODE_PACKAGE);
		versionEvidence.setResolvedValue(version);
		dependency.addProductEvidences(versionEvidence);
		//Add CPE enumeration
		CPENameModel cpeEnumeration = new CPENameModel();
		cpeEnumeration.setVendor(vendor);
		cpeEnumeration.setProduct(product);
		cpeEnumeration.setVersion(version);
		dependency.setCpeEnumeration(cpeEnumeration);
		return dependency;
	}
}
