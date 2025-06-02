package com.isteer.cvssanalyser.core;

import org.apache.commons.text.similarity.JaroWinklerSimilarity;

public class JWFuzzySearchTool {
	//Jaro-Winkler Similarity
	public double match(String input1,String input2) {
		JaroWinklerSimilarity jaroWinkler = new JaroWinklerSimilarity();
        double similarity = jaroWinkler.apply(input1,input2);
        return similarity;
	}
}
