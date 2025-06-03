package com.isteer.cvssanalyser.core.model;

public class ScoredCpeEntryModel {
	public CpeEntryModel entry;
    public double similarity;

    public ScoredCpeEntryModel(CpeEntryModel entry, double similarity) {
        this.entry = entry;
        this.similarity = similarity;
    }
}
