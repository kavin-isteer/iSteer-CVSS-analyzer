package com.isteer.cvssanalyser.core.lucene;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.dao.CPEEntriesDao;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class LuceneIndexRunner {
	DbUtil dbUtil = new DbUtil();
	CPEEntriesDao dao = new CPEEntriesDao();

	public void createIndexFromCvssDb() throws IOException, SQLException {
		// File indexDir = new File("lucene-index");
		// boolean indexExists = indexDir.exists() && indexDir.isDirectory() &&
		// indexDir.list().length > 0;

		Engine.logger.info("Fetching CPE entries from DB and indexing to lucene index...");

		// indexer
		LuceneCpeIndexer indexer = new LuceneCpeIndexer();
		indexer.open(); // open once

		int offset = 0;
		int limit = 100000;
		int totalIndexed = 0;

		try (Connection connection = dbUtil.getConnection()) {
			if (connection == null) {
				Engine.logger.error("Failed to establish database connection.");
				return;
			}
			while (true) {
				List<CpeEntryModel> batch = dao.getAllCpeEntriesWithOffset(connection, offset, limit);
				if (batch.isEmpty())
					break;

				indexer.indexBatch(batch);
				totalIndexed += batch.size();
				Engine.logger.info("Indexed batch of " + batch.size() + " records. Total: " + totalIndexed);

				offset += limit;
			}
		} catch (SQLException e) {
			Engine.logger.error("Error establishing database connection: " + e.getMessage());
			return;
		}

		indexer.close(); // close once at the end
		Engine.logger.info("Indexing complete. Total records indexed: " + totalIndexed);
	}
}
