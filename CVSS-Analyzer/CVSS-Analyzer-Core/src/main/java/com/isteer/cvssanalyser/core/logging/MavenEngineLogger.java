package com.isteer.cvssanalyser.core.logging;

import org.apache.maven.plugin.logging.Log;

public class MavenEngineLogger implements EngineLogger {
	private final Log mavenLog;

	public MavenEngineLogger(Log mavenLog) {
		this.mavenLog = mavenLog;
	}

	public void info(String msg) {
		mavenLog.info(msg);
	}

	public void warn(String msg) {
		mavenLog.warn(msg);
	}

	public void error(String msg) {
		mavenLog.error(msg);
	}

	public void debug(String msg) {
		mavenLog.debug(msg);
	}
}
