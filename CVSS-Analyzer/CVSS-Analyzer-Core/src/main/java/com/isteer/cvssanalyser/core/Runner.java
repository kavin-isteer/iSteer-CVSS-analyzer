package com.isteer.cvssanalyser.core;

import com.isteer.cvssanalyser.core.enums.EngineMode;

public class Runner {
		public static void main(String[] args) {
			Engine engine = new Engine();
			engine.analyze(EngineMode.POM);
		}
}
