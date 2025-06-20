package com.isteer.cvssanalyser.core.enums;

public enum HintAddedBy {
	CLIENT_USER(1),
	DEVELOPER(2);
	
	private int id;
	HintAddedBy(int id){
		this.id=id;
	}
	public int getId() {
		return id;
	}
	
	public static HintAddedBy fromId(int id) {
        for (HintAddedBy value : HintAddedBy.values()) {
            if (value.getId() == id) {
                return value;
            }
        }
        throw new IllegalArgumentException("Unknown HintAddedBy id: " + id);
    }
}
