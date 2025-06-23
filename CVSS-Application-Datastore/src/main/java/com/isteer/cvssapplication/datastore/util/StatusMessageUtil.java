package com.isteer.cvssapplication.datastore.util;

import org.springframework.context.MessageSource; // Importing Spring's MessageSource to handle internationalized messages.
import org.springframework.context.i18n.LocaleContextHolder; // Importing LocaleContextHolder to retrieve the current locale.
import org.springframework.stereotype.Component; // Importing Component annotation to mark this class as a Spring-managed bean.

import com.isteer.cvssapplication.datastore.enums.CVSSEnum;

@Component // Marks this class as a Spring component, enabling it to be auto-detected and managed by the Spring container.
public class StatusMessageUtil {

    // Static variable to hold the MessageSource instance for retrieving messages.
    private static MessageSource messageSource;

    // Constructor to inject the MessageSource dependency into the class.
    public StatusMessageUtil(MessageSource messageSource) {
        // Assigning the injected MessageSource instance to the static variable.
        StatusMessageUtil.messageSource = messageSource;
    }

    // Static method to retrieve a message based on the provided CVSSEnum value.
    public static String getMessage(CVSSEnum enumVal) {
        // Using the MessageSource to fetch the message corresponding to the key from the CVSSEnum.
        // LocaleContextHolder.getLocale() ensures the message is fetched for the current locale.
        return messageSource.getMessage(enumVal.getMessageKey(), null, LocaleContextHolder.getLocale());
    }
}
