package com.isteer.dto;

import java.util.List;

import com.isteer.entity.Application;
import com.isteer.entity.Computer;

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
