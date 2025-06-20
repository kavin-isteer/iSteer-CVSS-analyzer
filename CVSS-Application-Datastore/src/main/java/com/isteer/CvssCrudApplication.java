package com.isteer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class CvssCrudApplication {

	public static void main(String[] args) {
		SpringApplication.run(CvssCrudApplication.class, args);
	}

}
