package com.isteer.cvssanalyser.core.cache;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.dao.CPEEntriesDao;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class FuzzySearchCache {
    private static final AtomicReference<List<CpeEntryModel>> cachedCpeEntries = new AtomicReference<>();
    private static DbUtil dbUtil = new DbUtil();
	private static final Connection connection = dbUtil.getConnection();
	private static CPEEntriesDao entriesDao = new CPEEntriesDao();
    
    // Load from DB at startup or on demand
    public static void loadCache(List<CpeEntryModel> entriesFromDb) {
    	Engine.logger.info("Loading entries from db for cache.");
    	cachedCpeEntries.set(Collections.unmodifiableList(new ArrayList<>(entriesFromDb)));
    	Engine.logger.info("In memory cache finished.");
    }

    // Access cached data
    public static List<CpeEntryModel> getCachedWords() {
        return cachedCpeEntries.get();
    }

    // Optionally refresh manually or on a schedule
    public static void refreshCacheFromDb() {
        List<CpeEntryModel> freshData=new ArrayList<>();
		try {
			Engine.logger.info("Refreshing entries from db for cache.");
			freshData = entriesDao.getAllCpeEntries(connection);
			Engine.logger.info("In memory cache finished.");
		} catch (SQLException e) {
			e.printStackTrace();
			Engine.logger.info("");
		}
        loadCache(freshData);
    }
}
