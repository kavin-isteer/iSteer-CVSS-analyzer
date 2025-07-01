package com.isteer.cvssapplication.datastore.exception;

import com.isteer.cvssapplication.datastore.enums.CVSSEnum;

public class BussinessException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private final CVSSEnum error;

	public BussinessException(CVSSEnum IdException) {
		super(IdException.getMessageKey());
		this.error = IdException;
	}

	public CVSSEnum getError() {
		return error;
	}

}
