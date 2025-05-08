package com.isteer.cvssanalyser.core.util;

import java.awt.Desktop;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import com.isteer.cvssanalyser.core.model.DependencyModel;

public class HtmlReportGenerator {
    private final TemplateEngine templateEngine;
    
    public HtmlReportGenerator() {
        this.templateEngine = new TemplateEngine();
        ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setPrefix("/templates/");
        templateResolver.setSuffix(".html");
        templateEngine.setTemplateResolver(templateResolver);
    }
    
    public void generateReport(List<DependencyModel> dependencies, File outputDir) throws IOException {
        // Sort dependencies: vulnerable first (by vulnerability count descending, then name), then non-vulnerable (by name)
        List<DependencyModel> sortedDependencies = dependencies.stream()
            .sorted(Comparator.comparing(
                (DependencyModel dep) -> {
                    int vulnCount = dep.getVulnerabilities() != null ? dep.getVulnerabilities().size() : 0;
                    return vulnCount > 0 ? -vulnCount : 0; // Negative to sort descending for vulnerable
                }).thenComparing(DependencyModel::getDependencyName))
            .collect(Collectors.toList());
        
        // Compute summary statistics
        long vulnDeps = sortedDependencies.stream()
            .filter(dep -> dep.getVulnerabilities() != null && !dep.getVulnerabilities().isEmpty())
            .count();
        long totalVulns = sortedDependencies.stream()
            .mapToLong(dep -> dep.getVulnerabilities() != null ? dep.getVulnerabilities().size() : 0)
            .sum();
        
        Context context = new Context();
        context.setVariable("dependencies", sortedDependencies);
        context.setVariable("vulnDeps", vulnDeps);
        context.setVariable("totalVulns", totalVulns);
        
        String html = templateEngine.process("report", context);
        
        File reportFile = new File(outputDir, "dependency-report.html");
        try (FileWriter writer = new FileWriter(reportFile)) {
            writer.write(html);
        }
        
        // Optional: Open in default browser
        Desktop.getDesktop().browse(reportFile.toURI());
    }
}