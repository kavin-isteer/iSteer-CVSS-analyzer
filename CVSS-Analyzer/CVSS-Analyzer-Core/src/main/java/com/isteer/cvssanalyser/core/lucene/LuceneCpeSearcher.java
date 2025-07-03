package com.isteer.cvssanalyser.core.lucene;

import java.io.IOException;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;

public class LuceneCpeSearcher {
	private static final String INDEX_DIR = "lucene-index";
	private int EDIT_DISTANCE = 10; // Default edit distance
	private int TOP_MATCHES_THRESHOLD = 10; // Default match threshold

	public LuceneCpeSearcher withEditDistance(int editDistance) {
		this.EDIT_DISTANCE = editDistance;
		return this;
	}

	public LuceneCpeSearcher withTopMatchesThreshold(int matchThreshold) {
		if (matchThreshold > 0) {
			this.TOP_MATCHES_THRESHOLD = matchThreshold;
		}
		return this;
	}

	public List<CpeEntryModel> fuzzySearch(String field, String keyword) throws Exception {
		Directory dir = FSDirectory.open(Paths.get(INDEX_DIR));
		List<CpeEntryModel> results = new ArrayList<>();
		Engine.logger.info("Doing lucene search for - " + keyword);
		try (DirectoryReader reader = DirectoryReader.open(dir)) {
			IndexSearcher searcher = new IndexSearcher(reader);
			Analyzer analyzer = new StandardAnalyzer();
			String safeKeyword = QueryParser.escape(keyword);
			QueryParser parser = new QueryParser(field, analyzer);
			Query query = parser.parse(safeKeyword + "~" + this.EDIT_DISTANCE);

			TopDocs topDocs = searcher.search(query, TOP_MATCHES_THRESHOLD);
			for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
				Document doc = searcher.doc(scoreDoc.doc);

				CpeEntryModel entry = new CpeEntryModel();
				entry.setEntryId(Integer.parseInt(doc.get("entryId")));
				entry.setCpeName(doc.get("cpeName"));
				entry.setCpeTitle(doc.get("cpeTitle"));
				entry.setVendor(doc.get("vendor"));
				entry.setProduct(doc.get("product"));
				entry.setVersion(doc.get("version"));
				entry.setDeprecated(Boolean.parseBoolean(doc.get("isDeprecated")));

				if (doc.get("updatedDate") != null) {
					entry.setUpdatedDate(LocalDateTime.parse(doc.get("updatedDate")));
				}

				results.add(entry);
			}
		}

		return results;
	}

	public List<CpeEntryModel> multiFieldSearch(String vendorValue, String productValue) throws Exception {
		Engine.logger.info(
				"Lucene multifield search with vendor value: " + vendorValue + " and product value: " + productValue);
		List<CpeEntryModel> results = new ArrayList<>();

		Directory dir = FSDirectory.open(Paths.get("lucene-index"));
		try (DirectoryReader reader = DirectoryReader.open(dir)) {
			IndexSearcher searcher = new IndexSearcher(reader);
			Analyzer analyzer = new StandardAnalyzer();

			// Build queries
			Query vendorQuery = new QueryParser("vendor", analyzer).parse(vendorValue);
			Query productQuery = new QueryParser("product", analyzer).parse(productValue);

			// Combine
			BooleanQuery.Builder builder = new BooleanQuery.Builder();
			builder.add(vendorQuery, BooleanClause.Occur.MUST);
			builder.add(productQuery, BooleanClause.Occur.MUST);
			BooleanQuery query = builder.build();

			// Search
			TopDocs topDocs = searcher.search(query, TOP_MATCHES_THRESHOLD);
			for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
				Document doc = searcher.doc(scoreDoc.doc);
				CpeEntryModel entry = new CpeEntryModel();
				entry.setEntryId(Integer.parseInt(doc.get("entryId")));
				entry.setCpeName(doc.get("cpeName"));
				entry.setCpeTitle(doc.get("cpeTitle"));
				entry.setVendor(doc.get("vendor"));
				entry.setProduct(doc.get("product"));
				entry.setVersion(doc.get("version"));
				entry.setDeprecated(Boolean.parseBoolean(doc.get("isDeprecated")));

				if (doc.get("updatedDate") != null) {
					entry.setUpdatedDate(LocalDateTime.parse(doc.get("updatedDate")));
				}
				results.add(entry);
			}
		}
		Engine.logger.info("Returning results size: " + results.size());
		return results;
	}

	public List<CpeEntryModel> multiFieldSearch(List<String> vendorList, String productValue) throws Exception {
		List<CpeEntryModel> results = new ArrayList<>();
		Directory dir = FSDirectory.open(Paths.get("lucene-index"));
		try (DirectoryReader reader = DirectoryReader.open(dir)) {
			IndexSearcher searcher = new IndexSearcher(reader);
			Analyzer analyzer = new StandardAnalyzer();

			// Parse product query
			Query productQuery = new QueryParser("product", analyzer).parse(productValue);

			// Build vendor query using OR (SHOULD)
			BooleanQuery.Builder vendorQueryBuilder = new BooleanQuery.Builder();
			for (String vendor : vendorList) {
				Query vendorQuery = new QueryParser("vendor", analyzer).parse(vendor);
				vendorQueryBuilder.add(vendorQuery, BooleanClause.Occur.SHOULD);
			}
			BooleanQuery vendorQuery = vendorQueryBuilder.build();

			// Combine product AND vendor queries
			BooleanQuery.Builder finalQueryBuilder = new BooleanQuery.Builder();
			finalQueryBuilder.add(vendorQuery, BooleanClause.Occur.MUST); // match any of the vendors
			finalQueryBuilder.add(productQuery, BooleanClause.Occur.MUST); // must match product

			BooleanQuery finalQuery = finalQueryBuilder.build();

			// Execute search
			TopDocs topDocs = searcher.search(finalQuery, TOP_MATCHES_THRESHOLD);
			for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
				Document doc = searcher.doc(scoreDoc.doc);
				CpeEntryModel entry = new CpeEntryModel();
				entry.setEntryId(Integer.parseInt(doc.get("entryId")));
				entry.setCpeName(doc.get("cpeName"));
				entry.setCpeTitle(doc.get("cpeTitle"));
				entry.setVendor(doc.get("vendor"));
				entry.setProduct(doc.get("product"));
				entry.setVersion(doc.get("version"));
				entry.setDeprecated(Boolean.parseBoolean(doc.get("isDeprecated")));

				if (doc.get("updatedDate") != null) {
					entry.setUpdatedDate(LocalDateTime.parse(doc.get("updatedDate")));
				}
				results.add(entry);
			}
		}

		return results;
	}

	public List<CpeEntryModel> multiFieldSearch(List<String> vendorList, List<String> productList) throws Exception {
		List<CpeEntryModel> results = new ArrayList<>();
		Engine.logger.info("Doing multi-field search with vendorList size: " + vendorList.size()
				+ " productList size: " + productList.size());
		Directory dir = FSDirectory.open(Paths.get("lucene-index"));
		try (DirectoryReader reader = DirectoryReader.open(dir)) {
			IndexSearcher searcher = new IndexSearcher(reader);
			Analyzer analyzer = new StandardAnalyzer();

			BooleanQuery.Builder finalQueryBuilder = new BooleanQuery.Builder();
			// Parse product query
//			Query productQuery = new QueryParser("product", analyzer).parse(productValue);

			// Build vendor query using OR (SHOULD)
			BooleanQuery.Builder vendorQueryBuilder = new BooleanQuery.Builder();
			for (String vendor : vendorList) {
				Query vendorQuery = new QueryParser("vendor", analyzer).parse(vendor);
				vendorQueryBuilder.add(vendorQuery, BooleanClause.Occur.SHOULD);
			}
			BooleanQuery vendorQuery = vendorQueryBuilder.build();

			// Combine product AND vendor queries
//			BooleanQuery.Builder finalQueryBuilder = new BooleanQuery.Builder();
			finalQueryBuilder.add(vendorQuery, BooleanClause.Occur.MUST); // match any of the vendors
//			finalQueryBuilder.add(productQuery, BooleanClause.Occur.MUST); // must match product

			// Product query (OR among products)
			if (productList != null && !productList.isEmpty()) {
				BooleanQuery.Builder productQueryBuilder = new BooleanQuery.Builder();
				for (String product : productList) {
					Query productQuery = new QueryParser("product", analyzer).parse(QueryParser.escape(product));
					productQueryBuilder.add(productQuery, BooleanClause.Occur.SHOULD);
				}
				finalQueryBuilder.add(productQueryBuilder.build(), BooleanClause.Occur.MUST);
			}

			BooleanQuery finalQuery = finalQueryBuilder.build();

			// Execute search
			TopDocs topDocs = searcher.search(finalQuery, TOP_MATCHES_THRESHOLD);
			for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
				Document doc = searcher.doc(scoreDoc.doc);
				CpeEntryModel entry = new CpeEntryModel();
				entry.setEntryId(Integer.parseInt(doc.get("entryId")));
				entry.setCpeName(doc.get("cpeName"));
				entry.setCpeTitle(doc.get("cpeTitle"));
				entry.setVendor(doc.get("vendor"));
				entry.setProduct(doc.get("product"));
				entry.setVersion(doc.get("version"));
				entry.setDeprecated(Boolean.parseBoolean(doc.get("isDeprecated")));

				if (doc.get("updatedDate") != null) {
					entry.setUpdatedDate(LocalDateTime.parse(doc.get("updatedDate")));
				}
				results.add(entry);
			}
		}

		return results;
	}

	public List<CpeEntryModel> multiFieldSearch(List<String> vendorList, List<String> productList,
			List<String> versionList) throws Exception {
		List<CpeEntryModel> results = new ArrayList<>();
		Directory dir = FSDirectory.open(Paths.get("lucene-index"));
		Engine.logger.info("Doing all field match with vedorList size: " + vendorList.size() + " productList size: "
				+ productList.size() + " verisonList size: " + versionList.size());
		try (DirectoryReader reader = DirectoryReader.open(dir)) {
			IndexSearcher searcher = new IndexSearcher(reader);
			Analyzer analyzer = new StandardAnalyzer();

			BooleanQuery.Builder finalQueryBuilder = new BooleanQuery.Builder();

			// Vendor query (OR among vendors)
			if (vendorList != null && !vendorList.isEmpty()) {
				BooleanQuery.Builder vendorQueryBuilder = new BooleanQuery.Builder();
				for (String vendor : vendorList) {
					Query vendorQuery = new QueryParser("vendor", analyzer).parse(QueryParser.escape(vendor));
					vendorQueryBuilder.add(vendorQuery, BooleanClause.Occur.SHOULD);
				}
				finalQueryBuilder.add(vendorQueryBuilder.build(), BooleanClause.Occur.MUST);
			}

			// Product query (OR among products)
			if (productList != null && !productList.isEmpty()) {
				BooleanQuery.Builder productQueryBuilder = new BooleanQuery.Builder();
				for (String product : productList) {
					Query productQuery = new QueryParser("product", analyzer).parse(QueryParser.escape(product));
					productQueryBuilder.add(productQuery, BooleanClause.Occur.SHOULD);
				}
				finalQueryBuilder.add(productQueryBuilder.build(), BooleanClause.Occur.MUST);
			}
			if (versionList != null) {
				// Version query (OR among versions)
				if (versionList != null && !versionList.isEmpty()) {
					BooleanQuery.Builder versionQueryBuilder = new BooleanQuery.Builder();
					for (String version : versionList) {
						Query versionQuery = new QueryParser("version", analyzer).parse(QueryParser.escape(version));
						versionQueryBuilder.add(versionQuery, BooleanClause.Occur.SHOULD);
					}
					finalQueryBuilder.add(versionQueryBuilder.build(), BooleanClause.Occur.MUST);
				}
			}
			Query finalQuery = finalQueryBuilder.build();

			TopDocs topDocs = searcher.search(finalQuery, TOP_MATCHES_THRESHOLD);
			for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
				Document doc = searcher.doc(scoreDoc.doc);
				CpeEntryModel entry = new CpeEntryModel();
				entry.setEntryId(Integer.parseInt(doc.get("entryId")));
				entry.setCpeName(doc.get("cpeName"));
				entry.setCpeTitle(doc.get("cpeTitle"));
				entry.setVendor(doc.get("vendor"));
				entry.setProduct(doc.get("product"));
				entry.setVersion(doc.get("version"));
				entry.setDeprecated(Boolean.parseBoolean(doc.get("isDeprecated")));

				if (doc.get("updatedDate") != null) {
					entry.setUpdatedDate(LocalDateTime.parse(doc.get("updatedDate")));
				}

				results.add(entry);
			}
		} catch (Exception e) {
			Engine.logger.info("Error while doing multi-field search: " + e.getMessage());

		}
		Engine.logger.info("Returning fuzzy search results size: " + results.size());
		return results;
	}
	
	public List<CpeEntryModel> multiFieldSearch(String vendorValue, String productValue, String versionValue) throws Exception {
	    Engine.logger.info("Lucene multifield search with vendor: " + vendorValue + ", product: " + productValue + ", version: " + versionValue);
	    List<CpeEntryModel> results = new ArrayList<>();

	    if ((vendorValue == null || vendorValue.isBlank()) &&
	        (productValue == null || productValue.isBlank()) &&
	        (versionValue == null || versionValue.isBlank())) {
	        throw new IllegalArgumentException("At least one of vendor, product, or version must be provided.");
	    }

	    Directory dir = FSDirectory.open(Paths.get("lucene-index"));
	    try (DirectoryReader reader = DirectoryReader.open(dir)) {
	        IndexSearcher searcher = new IndexSearcher(reader);
	        Analyzer analyzer = new StandardAnalyzer();

	        BooleanQuery.Builder finalQueryBuilder = new BooleanQuery.Builder();

	        // VENDOR
	        if (vendorValue != null && !vendorValue.isBlank()) {
	            String normalizedVendor = normalize(vendorValue);
	            List<String> vendorTokens = getAnalyzedTokens("vendor", normalizedVendor, analyzer);
	            Engine.logger.info("Vendor tokens: " + vendorTokens);
	            BooleanQuery.Builder vendorQueryBuilder = new BooleanQuery.Builder();
	            for (String token : vendorTokens) {
	                vendorQueryBuilder.add(new TermQuery(new Term("vendor", token)), BooleanClause.Occur.SHOULD);
	            }
	            finalQueryBuilder.add(vendorQueryBuilder.build(), BooleanClause.Occur.MUST);
	        }

	        // PRODUCT
	        if (productValue != null && !productValue.isBlank()) {
	            String normalizedProduct = normalize(productValue);
	            List<String> productTokens = getAnalyzedTokens("product", normalizedProduct, analyzer);
	            Engine.logger.info("Product tokens: " + productTokens);
	            BooleanQuery.Builder productQueryBuilder = new BooleanQuery.Builder();
	            for (String token : productTokens) {
	                productQueryBuilder.add(new TermQuery(new Term("product", token)), BooleanClause.Occur.SHOULD);
	            }
	            finalQueryBuilder.add(productQueryBuilder.build(), BooleanClause.Occur.MUST);
	        }

	        // VERSION
	        if (versionValue != null && !versionValue.isBlank()) {
	        	List<String> versionTokens = getVersionPrefixes(versionValue);
	            Engine.logger.info("Version tokens: " + versionTokens);
	            BooleanQuery.Builder versionQueryBuilder = new BooleanQuery.Builder();
	            for (String token : versionTokens) {
	                versionQueryBuilder.add(new TermQuery(new Term("tokenizedVersion", token)), BooleanClause.Occur.SHOULD);
	            }
	            finalQueryBuilder.add(versionQueryBuilder.build(), BooleanClause.Occur.MUST);
	        }

	        Query query = finalQueryBuilder.build();

	        TopDocs topDocs = searcher.search(query, TOP_MATCHES_THRESHOLD);
	        Engine.logger.info("Lucene search executed, total hits: " + topDocs.totalHits.value);

	        for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
	            Document doc = searcher.doc(scoreDoc.doc);
	            CpeEntryModel entry = new CpeEntryModel();
	            entry.setEntryId(Integer.parseInt(doc.get("entryId")));
	            entry.setCpeName(doc.get("cpeName"));
	            entry.setCpeTitle(doc.get("cpeTitle"));
	            entry.setVendor(doc.get("vendor"));
	            entry.setProduct(doc.get("product"));
	            entry.setVersion(doc.get("version"));
	            entry.setDeprecated(Boolean.parseBoolean(doc.get("isDeprecated")));

	            if (doc.get("updatedDate") != null) {
	                entry.setUpdatedDate(LocalDateTime.parse(doc.get("updatedDate")));
	            }
	            results.add(entry);
	        }
	    }

	    Engine.logger.info("Returning results size: " + results.size());
	    return results;
	}


	private List<String> getAnalyzedTokens(String fieldName, String input, Analyzer analyzer) throws IOException {
	    List<String> tokens = new ArrayList<>();
	    TokenStream tokenStream = analyzer.tokenStream(fieldName, input);
	    CharTermAttribute attr = tokenStream.addAttribute(CharTermAttribute.class);
	    tokenStream.reset();
	    while (tokenStream.incrementToken()) {
	        tokens.add(attr.toString());
	    }
	    tokenStream.end();
	    tokenStream.close();
	    return tokens;
	}
	
	private String normalize(String input) {
	    return input.toLowerCase().replaceAll("[^a-z0-9\\s]", "").trim();
	}
	
	private List<String> getVersionPrefixes(String version) {
	    List<String> tokens = new ArrayList<>();
	    if (version == null || version.isBlank()) return tokens;

	    String[] parts = version.split("\\.");
	    StringBuilder builder = new StringBuilder();
	    for (int i = 0; i < parts.length; i++) {
	        if (i > 0) builder.append(".");
	        builder.append(parts[i]);
	        tokens.add(builder.toString());
	    }
	    return tokens;
	}

}
