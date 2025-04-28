package com.isteer.cvssanalyzer.api.controller;

import java.util.List;
import java.io.IOException;
import java.util.ArrayList;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.cvssanalyzer.api.service.CvssService;

@RestController
@RequestMapping("/cvss")
public class CvssController {
	private CvssService service;

	public CvssController(CvssService cvssService) {
		this.service = cvssService;
	}

	@GetMapping("/")
	public List<String> handshake1() {
		List<String> list = new ArrayList<>();
		list.add("Kavin");
		return list;
	}

	@GetMapping("/hi")
	public List<String> handshake() {
		try {
			return service.dummyValues();
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void main(String[] args) {
		CvssService service1 = new CvssService();
		List<String> list = new ArrayList<>();
		try {
			list = service1.dummyValues();
		} catch (IOException | InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for (String s : list) {
			System.out.println(s);
		}
	}
}
