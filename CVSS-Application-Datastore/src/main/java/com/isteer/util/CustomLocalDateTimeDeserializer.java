package com.isteer.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.io.IOException;

public class CustomLocalDateTimeDeserializer extends StdDeserializer<LocalDateTime> {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public CustomLocalDateTimeDeserializer() {
        this(null);
    }

    public CustomLocalDateTimeDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public LocalDateTime deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String date = p.getText();
        if (date == null || date.trim().isEmpty() || "null".equalsIgnoreCase(date)) {
            return null;
        }
        try {
            return LocalDateTime.parse(date, formatter);
        } catch (Exception e) {
            throw new BussinessException(CVSSEnum.INVALID_DATE_FORMAT);
        }
    }
}