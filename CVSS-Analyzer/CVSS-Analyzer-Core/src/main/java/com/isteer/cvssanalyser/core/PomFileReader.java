package com.isteer.cvssanalyser.core;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.springframework.web.multipart.MultipartFile;

import com.isteer.cvssanalyser.core.model.DependencyModel;

public class PomFileReader {
    /**
     * Analyzes a MultipartFile (expected to be a pom.xml) and extracts its direct dependencies.
     * Properties within the POM are *attempted* to be resolved for common scenarios.
     *
     * @param pomFile The uploaded pom.xml as a MultipartFile.
     * @return A list of DependencyModel objects.
     * @throws IOException If there's an error reading the uploaded file.
     * @throws XmlPullParserException If there's an error parsing the XML content.
     * @throws IllegalArgumentException If the uploaded file is empty or not a valid POM.
     */
    public List<DependencyModel> analyzePomFile(MultipartFile pomFile) throws IOException, XmlPullParserException {
        if (pomFile.isEmpty()) {
        	Engine.logger.error("Uploaded file is empty.");
        	throw new IllegalArgumentException("Uploaded file is empty.");
        }
        if (!pomFile.getOriginalFilename().endsWith(".xml")) {
            // Basic validation, you might want more robust content type checking
            Engine.logger.info("Warning: Uploaded file does not have a .xml extension: " + pomFile.getOriginalFilename());
        }

        MavenXpp3Reader reader = new MavenXpp3Reader();
        Model model = null;

        try (Reader fileReader = new InputStreamReader(pomFile.getInputStream())) {
            model = reader.read(fileReader);
        }

        if (model == null) {
        	Engine.logger.error("Could not parse POM model from the uploaded file.");
            throw new IllegalArgumentException("Could not parse POM model from the uploaded file.");
        }

        // --- Basic Property Resolution (as discussed in previous responses) ---
        // For full Maven-like property resolution (including inheritance from parent POMs,
        // profiles, and settings.xml), you'd use Maven's DefaultModelBuilder.
        // This simple approach handles properties defined directly in the current POM.

        Properties projectProperties = model.getProperties();
        Properties effectiveProperties = new Properties();
        if (projectProperties != null) {
            effectiveProperties.putAll(projectProperties);
        }
        // Add built-in Maven properties
        effectiveProperties.put("project.version", model.getVersion());
        effectiveProperties.put("project.groupId", model.getGroupId());
        effectiveProperties.put("project.artifactId", model.getArtifactId());
        effectiveProperties.put("pom.version", model.getVersion());
        effectiveProperties.put("pom.groupId", model.getGroupId());
        effectiveProperties.put("pom.artifactId", model.getArtifactId());


        List<DependencyModel> dependencyModels = new ArrayList<>();
        List<Dependency> mavenDependencies = model.getDependencies();

        if (mavenDependencies != null) {
            for (Dependency dep : mavenDependencies) {
                String groupId = resolveProperty(dep.getGroupId(), effectiveProperties);
                String artifactId = resolveProperty(dep.getArtifactId(), effectiveProperties);
                String version = resolveProperty(dep.getVersion(), effectiveProperties);
                String scope = resolveProperty(dep.getScope(), effectiveProperties);
               // String classifier = resolveProperty(dep.getClassifier(), effectiveProperties);
                
                String gavName = groupId+":"+artifactId+":"+"jar"+":"+version+":"+scope;
                dependencyModels.add(new DependencyModel(gavName));
            }
        }

        return dependencyModels;
    }

    /**
     * Simple utility to resolve properties like ${prop.name} from the given properties map.
     * This is a basic implementation and doesn't handle complex expressions or transitive properties.
     */
    private String resolveProperty(String value, Properties properties) {
        if (value == null || !value.contains("${")) {
            return value;
        }
        // Basic resolution: replace ${prop.name} with its value
        for (String propName : properties.stringPropertyNames()) {
            value = value.replace("${" + propName + "}", properties.getProperty(propName));
        }
        // Handle common built-in project/pom properties that might not be in the map yet (though we try to add them)
        if (value.contains("${project.version}") && properties.containsKey("project.version")) {
            value = value.replace("${project.version}", properties.getProperty("project.version"));
        }
        if (value.contains("${pom.version}") && properties.containsKey("pom.version")) {
            value = value.replace("${pom.version}", properties.getProperty("pom.version"));
        }
        // You might need more sophisticated property resolution if your POMs use complex expressions.
        return value;
    }
}
