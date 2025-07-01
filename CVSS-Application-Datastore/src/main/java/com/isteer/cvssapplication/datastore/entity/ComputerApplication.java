package com.isteer.cvssapplication.datastore.entity;

import java.time.LocalDateTime;

public class ComputerApplication {
	private Long id;

	private String uuid;
	private String computerUuid;
	private String applicationUuid;
	private LocalDateTime installedDate;
	private boolean isDeleted;
	private LocalDateTime createdAt;
	private LocalDateTime updatedAt;

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

	public String getComputerUuid() {
		return computerUuid;
	}

	public void setComputerUuid(String computerUuid) {
		this.computerUuid = computerUuid;
	}

	public String getApplicationUuid() {
		return applicationUuid;
	}

	public void setApplicationUuid(String applicationUuid) {
		this.applicationUuid = applicationUuid;
	}

	public LocalDateTime getInstalledDate() {
		return installedDate;
	}

	public void setInstalledDate(LocalDateTime installedDate) {
		this.installedDate = installedDate;
	}

	public boolean isDeleted() {
		return isDeleted;
	}

	public void setDeleted(boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}

	public LocalDateTime getUpdatedAt() {
		return updatedAt;
	}

	public void setUpdatedAt(LocalDateTime updatedAt) {
		this.updatedAt = updatedAt;
	}
}
