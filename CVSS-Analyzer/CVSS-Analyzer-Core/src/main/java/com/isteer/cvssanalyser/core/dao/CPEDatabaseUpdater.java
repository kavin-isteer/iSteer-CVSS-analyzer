package com.isteer.cvssanalyser.core.dao;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.*;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CPEDatabaseUpdater {

    private static final String NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0/";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/cpe_match";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "kavin123";

    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
           Statement st = conn.createStatement();
           st.execute("TRUNCATE TABLE cpe_entries");
        	conn.setAutoCommit(false);
            
            PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO cpe_entries (cpe_name, cpe_title, vendor, product, version, update_date, deprecated) " +
                "VALUES (?, ?, ?, ?, ?, NOW(), ?) " +
                "ON DUPLICATE KEY UPDATE cpe_title = VALUES(cpe_title), vendor = VALUES(vendor), " +
                "product = VALUES(product), version = VALUES(version), update_date = NOW(), deprecated = VALUES(deprecated)"
            );

            ObjectMapper mapper = new ObjectMapper();
            int startIndex = 0;
            int resultsPerPage = 10000;

            while (true) {
                String paginatedUrl = NVD_CPE_API + "?startIndex=" + startIndex + "&resultsPerPage=" + resultsPerPage;
                System.out.println("Fetching: " + paginatedUrl);
                URL url = new URL(paginatedUrl);
                HttpURLConnection connApi = (HttpURLConnection) url.openConnection();
                connApi.setRequestMethod("GET");
                connApi.setRequestProperty("apiKey", "ca987215-dbe8-42f0-a656-e5da368c3c70");

                if (connApi.getResponseCode() != 200) {
                    throw new RuntimeException("HTTP error: " + connApi.getResponseCode());
                }

                BufferedReader in = new BufferedReader(new InputStreamReader(connApi.getInputStream()));
                JsonNode root = mapper.readTree(in);
                JsonNode cpes = root.path("products");

                if (!cpes.isArray() || cpes.size() == 0) break;

                for (JsonNode node : cpes) {
                	JsonNode cpe= node.path("cpe");
                	String cpeName = cpe.has("cpe23Uri")
                	    ? cpe.path("cpe23Uri").asText()
                	    : cpe.path("cpeName").asText();

                    String title = "";
                    JsonNode titles = cpe.path("titles");
                    if (titles.isArray() && titles.size() > 0) {
                        title = titles.get(0).path("title").asText();
                    }

                    boolean deprecated = cpe.path("deprecated").asBoolean(false);

                    // Extract vendor/product/version
                    String[] parts = cpeName.split(":");
                    String vendor = parts.length > 3 ? parts[3] : "";
                    String product = parts.length > 4 ? parts[4] : "";
                    String version = parts.length > 5 ? parts[5] : "";
              //      System.out.printf("Parsed CPE: %s | Vendor: %s | Product: %s | Version: %s%n",
              //              cpeName, vendor, product, version);
                    stmt.setString(1, cpeName);
                    stmt.setString(2, title);
                    stmt.setString(3, vendor);
                    stmt.setString(4, product);
                    stmt.setString(5, version);
                    stmt.setBoolean(6, deprecated);
                    stmt.addBatch();
                }

                stmt.executeBatch();
                conn.commit();

                int totalResults = root.path("totalResults").asInt();
                startIndex += resultsPerPage;

                if (startIndex >= totalResults) break;
            }

            stmt.close();
            System.out.println("NVD Data Import completed.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}