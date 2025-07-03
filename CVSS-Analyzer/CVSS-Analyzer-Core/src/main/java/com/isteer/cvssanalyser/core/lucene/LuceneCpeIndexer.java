package com.isteer.cvssanalyser.core.lucene;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;

import com.isteer.cvssanalyser.core.model.CpeEntryModel;
public class LuceneCpeIndexer {
	 private static final String INDEX_DIR = "lucene-index";
	    private IndexWriter indexWriter;

	    // Initialize IndexWriter (once)
	    public void open() throws IOException {
	        if (indexWriter == null) {
	            Directory directory = FSDirectory.open(Paths.get(INDEX_DIR));
	            Analyzer analyzer = new StandardAnalyzer();
	            IndexWriterConfig config = new IndexWriterConfig(analyzer);
	            config.setOpenMode(IndexWriterConfig.OpenMode.CREATE); // Create new index (once)
	            indexWriter = new IndexWriter(directory, config);
	        }
	    }

	    // Add batch of documents
	    public void indexBatch(List<CpeEntryModel> entries) throws IOException {
	        for (CpeEntryModel entry : entries) {
	            Document doc = new Document();

	            doc.add(new StringField("entryId", String.valueOf(entry.getEntryId()), Field.Store.YES));
	            doc.add(new TextField("cpeName", entry.getCpeName(), Field.Store.YES));
	            doc.add(new TextField("cpeTitle", entry.getCpeTitle(), Field.Store.YES));
	            doc.add(new TextField("vendor", entry.getVendor(), Field.Store.YES));
	            doc.add(new TextField("product", entry.getProduct(), Field.Store.YES));
	            doc.add(new TextField("version", entry.getVersion(), Field.Store.YES));
	            String versionPrefixes = String.join(" ", getVersionPrefixes(entry.getVersion()));
	            doc.add(new TextField("tokenizedVersion", versionPrefixes, Field.Store.YES));
	            doc.add(new StringField("isDeprecated", String.valueOf(entry.isDeprecated()), Field.Store.YES));

	            if (entry.getUpdatedDate() != null) {
	                doc.add(new StringField("updatedDate", entry.getUpdatedDate().toString(), Field.Store.YES));
	            }

	            indexWriter.addDocument(doc);
	        }
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

	    // Finalize and close writer (once)
	    public void close() throws IOException {
	        if (indexWriter != null) {
	            indexWriter.flush();
	            indexWriter.commit();
	            indexWriter.close();
	            indexWriter = null;
	        }
	    }
}
