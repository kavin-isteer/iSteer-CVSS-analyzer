package com.isteer.cvssapplication.datastore.dto;

import java.util.List;

import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Computer;

public class ComputerDetailsResponseDTO {

	private Computer computer;

	private List<Application> applications;

	public Computer getComputer() {
		return computer;
	}

	public void setComputer(Computer computer) {
		this.computer = computer;
	}

	public List<Application> getApplications() {
		return applications;
	}

	public void setApplications(List<Application> applications) {
		this.applications = applications;
	}

}
