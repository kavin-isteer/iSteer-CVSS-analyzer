package com.isteer.cvssanalyser.core;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.maven.cli.MavenCli;


public class DependencyTreeResolver {

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
