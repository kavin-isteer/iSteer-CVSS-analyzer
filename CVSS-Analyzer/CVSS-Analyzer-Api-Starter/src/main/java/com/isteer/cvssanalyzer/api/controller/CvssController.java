package com.isteer.cvssanalyzer.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.cvssanalyzer.api.service.CvssService;

@RestController
@RequestMapping("/cvss")
public class CvssController {
	private CvssService service;
	public CvssController(CvssService cvssService) {
		this.service=cvssService;
	}
	
	@GetMapping
	public String handshake() {
		return "Hi";
	}
}
