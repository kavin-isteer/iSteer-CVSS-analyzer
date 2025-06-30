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
    	Engine.logger.info("Fetching CPE entries from cache");
        return cachedCpeEntries.get();
    }

    // Optionally refresh manually or on a schedule
    public static void refreshCacheFromDb() {
    	if(cachedCpeEntries.get().size()>0) {
    		return;
    	}
        List<CpeEntryModel> freshData=new ArrayList<>();
        try {
        	Engine.logger.info("Refreshing CPE entries cache from database");
            freshData = entriesDao.getAllCpeEntries(connection);
            Engine.logger.info("Fetched " + freshData.size() + " CPE entries from database");
        } catch (SQLException e) {
            e.printStackTrace();
            Engine.logger.error("Error fetching CPE entries from database: " + e.getMessage());
        }
        loadCache(freshData);
    }
}
