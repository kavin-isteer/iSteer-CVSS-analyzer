package com.isteer.cvssanalyser.core.logging;

public interface EngineLogger {
	void info(String msg);
    void warn(String msg);
    void error(String msg);
    void debug(String msg);
}
