package com.isteer.cvssanalyser.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;


public class DependencyTreeResolver {

	/**
     * Fetches the list of dependencies from the Maven project by executing the
     * `mvn dependency:tree` command in the given project directory.
     *
     * @param projectDir The directory containing the Maven project (should include a valid pom.xml)
     * @return A list of dependencies extracted from the Maven output
     * @throws IOException If there is an error during process I/O
     * @throws InterruptedException If the process execution is interrupted
     */
    public List<String> fetchDependencies(File projectDir) throws IOException, InterruptedException {
    	List<String> dependencies = new ArrayList<>();

        ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", "mvn", "dependency:tree", "-DoutputType=text");
        builder.directory(projectDir);
        builder.redirectErrorStream(true); // merge stderr into stdout
        Process process = builder.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Check if the line represents a dependency (direct or transitive)
                if (line.contains("+-") || line.contains("\\+--") || line.contains("|  +-") || line.contains("|  \\--")) {
                    // Clean up the line to just get the dependency info
                	int index = line.indexOf(':');
                	String dependency="";
                	if (index > 0) {
                	    dependency = line.substring(line.lastIndexOf(' ', index)).trim();
                	}
                    dependencies.add(dependency);
                }
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Maven command failed with exit code: " + exitCode);
        }

        return dependencies;
    }
}
