package com.isteer.cvssapplication.datastore.configuration;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration // Marks this class as a configuration class for Spring
public class SecurityConfiguration {

    @Bean // Defines a Spring bean for configuring CORS settings
    CorsConfigurationSource corsConfigurationSource() {
        // Create a new CORS configuration object
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Specify the allowed origins (domains) for cross-origin requests
        configuration.setAllowedOrigins(List.of("http://127.0.0.1:5500", "http://localhost:4200"));
        
        // Specify the allowed HTTP methods for cross-origin requests
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        
        // Specify the allowed headers that can be included in cross-origin requests
        configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
        
        // Allow credentials (e.g., cookies, authorization headers) to be included in cross-origin requests
        configuration.setAllowCredentials(true);

        // Create a URL-based CORS configuration source
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        
        // Register the CORS configuration for all endpoints (/**)
        source.registerCorsConfiguration("/**", configuration);
        
        // Return the configured CORS source
        return source;
    }

    @Bean // Defines a Spring bean for the CORS filter
    CorsFilter corsFilter() {
        // Create and return a new CORS filter using the configured CORS source
        return new CorsFilter(corsConfigurationSource());
    }
}
