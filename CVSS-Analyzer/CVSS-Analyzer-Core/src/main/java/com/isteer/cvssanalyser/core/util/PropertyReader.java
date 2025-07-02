package com.isteer.cvssanalyser.core.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import com.isteer.cvssanalyser.core.Engine;

public class PropertyReader {

    public static String getProperty(String key) {
        Properties props = new Properties();
        try (InputStream input = PropertyReader.class.getClassLoader().getResourceAsStream("application.properties")) {
            if (input == null) {
                throw new RuntimeException("Unable to find application.properties");
            }
            props.load(input);
            return props.getProperty(key);
        } catch (IOException ex) {
            throw new RuntimeException("Error reading properties file", ex);
        }
    }

}