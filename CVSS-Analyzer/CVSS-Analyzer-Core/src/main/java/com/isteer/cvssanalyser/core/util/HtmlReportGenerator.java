package com.isteer.cvssanalyser.core.util;

import java.awt.Desktop;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
	    	
	        Context context = new Context();
	        context.setVariable("dependencies", dependencies);
	        
	        String html = templateEngine.process("report", context);
	        
	        File reportFile = new File(outputDir, "dependency-report.html");
	        try (FileWriter writer = new FileWriter(reportFile)) {
	            writer.write(html);
	        }
	        
	        // Optional: Open in default browser
	        Desktop.getDesktop().browse(reportFile.toURI());
	    }
}
