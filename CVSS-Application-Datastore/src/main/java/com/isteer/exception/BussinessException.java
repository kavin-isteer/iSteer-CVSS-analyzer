package com.isteer.exception;

import com.isteer.enums.CVSSEnum;

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
		
		
	


		public BussinessException(int statusCode, String message) {
			this.error = null;
			// TODO Auto-generated constructor stub
		}





		public  CVSSEnum getError() {
			return error;
		}

}
