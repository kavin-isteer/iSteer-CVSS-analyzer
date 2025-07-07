package com.isteer.cvssapplication.datastore.entity;

import java.time.LocalDateTime;

public class CpeName {

	private long id;

	private String uuid;

	private String applicationUuid;

	private String cpeName;

	private boolean isResolvedByDb;

	private LocalDateTime createdAt;

	private LocalDateTime updatedAt;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getApplicationUuid() {
		return applicationUuid;
	}

	public void setApplicationUuid(String applicationUuid) {
		this.applicationUuid = applicationUuid;
	}

	public String getCpeName() {
		return cpeName;
	}

	public void setCpeName(String cpeName) {
		this.cpeName = cpeName;
	}

	public boolean isResolvedByDb() {
		return isResolvedByDb;
	}

	public void setResolvedByDb(boolean isResolvedByDb) {
		this.isResolvedByDb = isResolvedByDb;
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

	@Override
	public String toString() {
		return "CpeNameModel [id=" + id + ", uuid=" + uuid + ", applicationUuid=" + applicationUuid + ", cpeName="
				+ cpeName + ", isResolvedByDb=" + isResolvedByDb + ", createdAt=" + createdAt + ", updatedAt="
				+ updatedAt + "]";
	}
}
