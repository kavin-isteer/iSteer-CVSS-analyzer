package com.isteer.cvssanalyser.core.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Slf4jEngineLogger implements EngineLogger {
	private final Logger logger = LoggerFactory.getLogger("Engine");

	public void info(String msg) {
		logger.info(msg);
	}

	public void warn(String msg) {
		logger.warn(msg);
	}

	public void error(String msg) {
		logger.error(msg);
	}

	public void debug(String msg) {
		logger.debug(msg);
	}
}
