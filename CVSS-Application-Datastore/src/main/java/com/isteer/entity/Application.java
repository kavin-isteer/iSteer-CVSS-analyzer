package com.isteer.entity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class Application {
	private Long id;

	@NotBlank(message = "UUID cannot be blank")
	@Size(min = 36, max = 36, message = "UUID must be 36 characters")
	private String uuid;

	@NotBlank(message = "Name cannot be blank")
	@Size(max = 100, message = "Name must be at most 100 characters")
	private String name;

	@Size(max = 50, message = "Version must be at most 50 characters")
	private String version;

	@NotBlank(message = "Vendor name cannot be blank")
	@Size(max = 100, message = "Vendor name must be at most 100 characters")
	private String vendorName;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getVendorName() {
		return vendorName;
	}

	public void setVendorName(String vendorName) {
		this.vendorName = vendorName;
	}


}