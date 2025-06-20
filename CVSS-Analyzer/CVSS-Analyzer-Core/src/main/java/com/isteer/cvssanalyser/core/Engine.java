package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.enums.CpeField;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.enums.ResolveMethod;
import com.isteer.cvssanalyser.core.logging.EngineLogger;
import com.isteer.cvssanalyser.core.logging.Slf4jEngineLogger;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityCvssMetricsModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityDetailsModel;
import com.isteer.cvssanalyser.core.util.HtmlReportGenerator;

public class Engine {
	public static List<DependencyModel> dependencies;

	public static EngineLogger logger = new Slf4jEngineLogger();

	public static EngineMode analysisMode;

	public static Double thresholdValue = 8.0;

	public static EngineLogger getLogger() {
		return logger;
	}

	public static void withDependencies(List<DependencyModel> dependencies) {
		Engine.dependencies = dependencies;
		return;
	}

	public static void withLogger(EngineLogger logger) {
		Engine.logger = logger;
		return;
	}

	public static void withThresholdValue(Double threshold) {
		logger.info("Setting threshold value to " + threshold);
		Engine.thresholdValue = threshold;
		return;
	}

	/**
	 * Starts the analysis based on the given engine mode.
	 * 
	 * @param analyzeMode The mode to run (POM or MAVEN_PLUGIN)
	 * @param emitter     Optional SSE emitter to stream progress back to client.
	 */
	public static void analyze(EngineMode analyzeMode, SseEmitter emitter) {
		Engine.analysisMode = analyzeMode;
		if (analyzeMode == EngineMode.POM) {
			analyzePom(emitter);
		} else if (analyzeMode == EngineMode.MAVEN_PLUGIN) {
			analyzeMavenPlugin();
		}

	}

	/**
	 * Legacy version of POM analysis without live progress updates. Deprecated and
	 * replaced by analyzePom(SseEmitter).
	 */
	@Deprecated
	private static void analyzePom() {
		GAVAnalyzer gavAnalyzer = new GAVAnalyzer();
		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		CveClient cveClient = new CveClient();

		dependencies = gavAnalyzer.fetchProjectDependenciesFromMavenTree();
		gavAnalyzer.collectGAVEvidencesFromDependencyName(dependencies);
		normalizer.normalizeDependencyEvidences(dependencies);
		int dependencyCount = 0;
		for (DependencyModel dep : dependencies) {
			cveClient.fetchVulnerabilitiesForDependency(dep);
			dependencyCount++;
			if (dependencyCount % 25 == 0) {
				try {

					String message = "Fetched vulnerabilities for " + dependencyCount + " out of" + dependencies.size()
							+ " dependencies";
					System.out.println(message);
					Thread.sleep(10000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
		int notResolvedCPEs = 0;
		List<String> notResolvedCPEnames = new ArrayList<>();
		for (DependencyModel dep : dependencies) {
			if (dep.getCpeEnumeration() == null) {
				notResolvedCPEnames.add(dep.getDependencyName());
				notResolvedCPEs++;
				continue;
			}
			if (dep.getVulnerabilities().size() > 0) {
				System.out.println("Found " + dep.getVulnerabilities().size() + " vulnerabilities for dependency:"
						+ dep.getDependencyName());
			} else {
				System.out.println("No vulnerabilities found for dependency: " + dep.getDependencyName() + " CPE: "
						+ dep.getCpeEnumeration().getCPE23Uri());
			}
		}
		System.out.println("Unable to resolve CPE names for " + notResolvedCPEs + " dependencies.");
		notResolvedCPEnames.forEach(System.out::println);
	}

	/**
	 * Performs vulnerability analysis in POM (Project Object Model) mode.
	 * 
	 * <p>
	 * This method is responsible for:
	 * </p>
	 * <ul>
	 * <li>Extracting all project dependencies using the Maven tree.</li>
	 * <li>Generating GAV (Group, Artifact, Version) evidence for each
	 * dependency.</li>
	 * <li>Normalizing CPE (Common Platform Enumeration) evidence to identify
	 * software products.</li>
	 * <li>Querying the NVD (National Vulnerability Database) API to fetch known
	 * vulnerabilities for each CPE.</li>
	 * </ul>
	 * 
	 * <p>
	 * Additionally, this method uses Server-Sent Events (SSE) to provide real-time
	 * progress updates to the frontend, which is useful for long-running
	 * operations.
	 * </p>
	 * 
	 * <p>
	 * Progress messages are sent as JSON every few dependencies processed,
	 * containing:
	 * </p>
	 * <ul>
	 * <li>fetchedDependencies: The number of dependencies processed so far.</li>
	 * <li>totalDependencies: The total number of dependencies to process.</li>
	 * </ul>
	 *
	 * <p>
	 * Example JSON emitted: {"fetchedDependencies": 12, "totalDependencies": 36}
	 * </p>
	 * 
	 * <p>
	 * This is useful in a web UI context where the client can display live progress
	 * to the user.
	 * </p>
	 * 
	 * @param emitter SSE emitter used to send real-time progress messages to the
	 *                frontend
	 */
	private static void analyzePom(SseEmitter emitter) {
		GAVAnalyzer gavAnalyzer = new GAVAnalyzer();
		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		CveClient cveClient = new CveClient();
		int dependencyCount = 0;
		// invoke analyzer to fetch the project dependencies from Maven tree.
		dependencies = gavAnalyzer.fetchProjectDependenciesFromMavenTree();
		gavAnalyzer.collectGAVEvidencesFromDependencyName(dependencies);
		// invoke normalizer to normalize the collected evidence to corresponding
		// resolved value from dependency hints database.
		normalizer.normalizeDependencyEvidences(dependencies);
		// iterate through dependencies and fetch vulnerabilities by invoking NVD api.
		for (DependencyModel dep : dependencies) {
			cveClient.fetchVulnerabilitiesForDependency(dep);
			dependencyCount++;
			// For evry 6 dependencies wait for 1.5 seconds to avoid API rate limiting
			// issue.
			if (dependencyCount % 6 == 0 || dependencyCount == dependencies.size()) {
				try {

					String message = String.format("{\"fetchedDependencies\": %d, \"totalDependencies\": %d }",
							dependencyCount, dependencies.size());
					logger.info(message);
					// send progress message as emitter event
					emitter.send(SseEmitter.event().data(message));
					Thread.sleep(1500);
				} catch (InterruptedException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		for (DependencyModel dep : dependencies) {
			if (dep.getVulnerabilities().size() > 0) {
				logger.info("Found " + dep.getVulnerabilities().size() + " vulnerabilities for dependency:"
						+ dep.getDependencyName());
			} else {
				logger.info("No vulnerabilities found for dependency: " + dep.getDependencyName());
			}
		}
	}

	/**
	 * Analyzes dependencies when run as a Maven plugin.
	 * <p>
	 * Steps performed:
	 * </p>
	 * <ul>
	 * <li>Collect GAV (Group, Artifact, Version) evidences from dependencies.</li>
	 * <li>Extract evidences from JAR files.</li>
	 * <li>Normalize evidences into CPE names.</li>
	 * <li>Fetch vulnerabilities for dependencies with resolved CPEs.</li>
	 * </ul>
	 * <p>
	 * Requires an internet connection to access the NVD API.
	 * </p>
	 */
	private static void analyzeMavenPlugin() {
		JarAnalyzer jarAnalyzer = new JarAnalyzer();
		GAVAnalyzer gavAnalyser = new GAVAnalyzer();
		CveClient cveClient = new CveClient();
		int dependencyCount = 0;
		// Invoke GAV analyser to collect GAV evidences from Dependency name
		gavAnalyser.collectGAVEvidencesFromDependencyName(dependencies);
		// invoke Jar analyzer to collect manifest evidences from jar file
		jarAnalyzer.collectEvidencesFromJar(dependencies);

		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		logger.info("Resolving evidences to CPE names.......");
		// invoke normalizer to normalize dependency evidences to resolved value using
		// hints database
		normalizer.normalizeDependencyEvidences(dependencies);
		logger.info(
				"Fetching vulnerability details for the dependencies from the NVD api(This step requires Internet connection!!)");
		// iterate through dependencies and fetch vulnerabilities by invoking NVD api.
		for (DependencyModel dep : dependencies) {
			if (dep.getCpeEnumeration() != null) {
				dependencyCount++;
				cveClient.fetchVulnerabilitiesForDependency(dep);
			}
			// For every 6 dependencies wait for 1.5 seconds to avoid API rate limiting
			// issue.
			if (dependencyCount % 6 == 0) {
				try {
					logger.info("Fetched vulnerabilities for " + dependencyCount + " out of " + dependencies.size()
							+ " dependencies");
					Thread.sleep(1500); // Sleep for 1.5 seconds to avoid hitting API rate limits
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Generates an HTML report of all analyzed dependencies and their
	 * vulnerabilities.
	 */
	public static void GenerateReport() {
		logger.info("Generating dependencies vulnerability report....");
		File reportFile = new File("target/");
		HtmlReportGenerator reportGenerator = new HtmlReportGenerator();
		try {
			reportGenerator.generateReport(dependencies, reportFile);
			logger.info("Report successfully generated and saved in target\\dependency-report.html");
		} catch (IOException e) {
			logger.error("Error occured during generating report");
			e.printStackTrace();
		}
	}

	/**
	 * Performs a fuzzy search for likely CPEs for dependencies that have no
	 * vulnerabilities. This is useful when the CPE could not be resolved or when no
	 * vulnerabilities were found.
	 */
	public static void doFuzzySearchAndGetLikelyCpes() {
		for (DependencyModel dep : dependencies) {
			if(dep.getCpeEnumeration()!=null) {
				boolean conditionToSkip =false;
				
				Map<CpeField, ResolveMethod> resolveMethod = dep.getCpeEnumeration().getResolveMethod();
				ResolveMethod vendorMethod = resolveMethod.get(CpeField.VENDOR);
				ResolveMethod productMethod = resolveMethod.get(CpeField.PRODUCT);

				if (isUserHint(vendorMethod)) {
					if(isUserHint(productMethod)) {
					    conditionToSkip = true;
					}
				}
				if (conditionToSkip) {
					continue;
				}
			}
			
			if (dep.getVulnerabilities().size() == 0) {
				logger.info("No vulnerabilities found for dependency: " + dep.getDependencyName()
						+ " Doing fuzzy search to find likely CPEs!!");
				FuzzySearchTool fuzzySearchTool = new FuzzySearchTool();
				try {
					// invoke the fuzzy search tool and search for likely CPEs.
					fuzzySearchTool.searchForLikelyCpes(dep);
				} catch (SQLException e) {
					// e.printStackTrace();
				}
			}
		}
	}
	
	private static boolean isUserHint(ResolveMethod method) {
	    return method == ResolveMethod.HINT_BY_CLIENT_USER || method == ResolveMethod.HINT_BY_DEVELOPER;
	}

	/**
	 * Checks if any dependencies have vulnerabilities with a CVSS base score above
	 * the threshold value.
	 * 
	 * @return true if any dependency has a vulnerability with a base score above
	 *         the threshold, false otherwise
	 */
	public static boolean checkForVulnerabilityForDependencies() {
		logger.info("Checking dependencies vulnerabilities with base score threshold value of " + thresholdValue);
		boolean isThresholdExceeded = false;
		// Iterate through the dependencies and check for vulnerabilities with score
		// greater than the threshold value.
		for (DependencyModel dep : dependencies) {
			if (dep.getVulnerabilities().size() > 0) {
				logger.error("Found " + dep.getVulnerabilities().size() + " vulnerabilities for dependency:"
						+ dep.getDependencyName());
				for (VulnerabilityDetailsModel vulnerabilities : dep.getVulnerabilities()) {
					logger.info(vulnerabilities.getCveId());
					for (VulnerabilityCvssMetricsModel cvssMetrics : vulnerabilities.getCvssMetrics()) {
						// FIXME: check whether these else conditions are needed
						if (cvssMetrics.getBaseScore() >= thresholdValue) {
							/*
							 * getMavenLog().info(""); getMavenLog().
							 * error("Vulnerability found with CVSS score greater than threshold value: "
							 * +thresholdValue+"\n"+ "Vulnerability ID: "+vulnerabilities.getCveId()+" "+
							 * "CVSS Score: "+cvssMetrics.getBaseScore());
							 */
							isThresholdExceeded = true;
						} else {
							/*
							 * getMavenLog().info(""); getMavenLog().
							 * error("Vulnerability found with CVSS score less than threshold value: "
							 * +thresholdValue+"\n"+ "Vulnerability ID: "+vulnerabilities.getCveId()+" "+
							 * "CVSS Score: "+cvssMetrics.getBaseScore());
							 */
						}
					}
				}
			} else {
				// getMavenLog().info("No vulnerabilities found for dependency: "+
				// dep.getDependencyName());
			}
		}
		/*
		 * if(isThresholdExceeded) { throw new
		 * RuntimeException("One or more dependencies found with vulnerability with base score greater than threshold value: "
		 * +thresholdValue+". Check report for more details!!"); }
		 */
		return isThresholdExceeded;
	}

	public static void readAndAnalyzeUploadedPomFile(MultipartFile file, SseEmitter emitter) {
		PomFileReader pomReader = new PomFileReader();
		GAVAnalyzer gavAnalyzer = new GAVAnalyzer();
		CPEEvidencesNormalizer normalizer = new CPEEvidencesNormalizer();
		try {
			dependencies = pomReader.analyzePomFile(file);
			gavAnalyzer.collectGAVEvidencesFromDependencyName(dependencies);
			// invoke normalizer to normalize the collected evidence to corresponding
			// resolved value from dependency hints database.
			normalizer.normalizeDependencyEvidences(dependencies);
			fetchVulnerabilities(emitter);
			doFuzzySearchAndGetLikelyCpes();
			emitter.send(SseEmitter.event().data("Analysis Completed"));
		} catch (IOException | XmlPullParserException e) {
			logger.info("Error reading and analyzing the uploaded pom file!!");
			e.printStackTrace();
		}
	}

	public static void readAndAnalyzeUploadedNodePackageFile(String packageJsonFile, String packageLockJsonFile,
			SseEmitter emitter) {
		NodePackageReader nodePackageReader = new NodePackageReader();
		try {
			dependencies = nodePackageReader.analyze(packageJsonFile, packageLockJsonFile);
			fetchVulnerabilities(emitter);
			doFuzzySearchAndGetLikelyCpes();
			emitter.send(SseEmitter.event().data("Analysis Completed"));
		} catch (Exception e) {
			e.printStackTrace();
			logger.info("Error while reading and analysing uploaded node package file!!");
		}
	}

	public static void fetchVulnerabilities(SseEmitter emitter) {
		CveClient cveClient = new CveClient();
		int dependencyCount = 0;
		try {
			// iterate through dependencies and fetch vulnerabilities by invoking NVD api.
			for (DependencyModel dep : dependencies) {
				cveClient.fetchVulnerabilitiesForDependency(dep);
				dependencyCount++;
				// For evry 6 dependencies wait for 1.5 seconds to avoid API rate limiting
				// issue.
				if (dependencyCount % 6 == 0 || dependencyCount == dependencies.size()) {
					try {

						String message = String.format("{\"fetchedDependencies\": %d, \"totalDependencies\": %d }",
								dependencyCount, dependencies.size());
						logger.info(message);
						if (emitter != null) {
							// send progress message as emitter event
							emitter.send(SseEmitter.event().data(message));
						}
						Thread.sleep(1500);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
			for (DependencyModel dep : dependencies) {
				if (dep.getVulnerabilities().size() > 0) {
					logger.info("Found " + dep.getVulnerabilities().size() + " vulnerabilities for dependency:"
							+ dep.getDependencyName());
				} else {
					logger.info("No vulnerabilities found for dependency: " + dep.getDependencyName());
				}
			}
		} catch (Exception e) {
			logger.info("Error fetching vulnerability from NVD Api!!");
			e.printStackTrace();
		}

	}
}
