package com.isteer.dto;

public class ApplicationInfo {
	private String uuid;
    private String name;
    private ComputerInfo computer;

    // Getters and setters
    public String getUuid() { return uuid; }
    public void setUuid(String uuid) { this.uuid = uuid; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public ComputerInfo getComputer() { return computer; }
    public void setComputer(ComputerInfo computer) { this.computer = computer; }

}
