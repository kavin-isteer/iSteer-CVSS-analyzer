package com.isteer.cvssanalyzer.api;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.isteer.cvssanalyzer.api.controller.CvssController;
import com.isteer.cvssanalyzer.api.service.CvssService;

@Configuration
@ConditionalOnClass(CvssService.class)
public class CvssAnalyzerConfiguration {
	@Bean
	CvssService getCvssService() {
		return new CvssService();
	}
	
	@Bean
	CvssController getCvssController(CvssService service) {
		return new CvssController(service);
	}
}
