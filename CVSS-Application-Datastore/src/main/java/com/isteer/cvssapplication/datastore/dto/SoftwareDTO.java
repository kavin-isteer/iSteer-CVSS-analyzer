package com.isteer.cvssapplication.datastore.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.isteer.cvssapplication.datastore.util.CustomLocalDateTimeDeserializer;

import jakarta.validation.constraints.NotBlank;

public  class SoftwareDTO {
	
	    @NotBlank(message = "Software name cannot be blank")
        private String name;
        private String version;
        private String vendorName;	  
        @JsonDeserialize(using = CustomLocalDateTimeDeserializer.class)
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
        private LocalDateTime installedDate;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
        private LocalDateTime createdAt;

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

		public LocalDateTime getInstalledDate() {
			return installedDate;
		}

		public void setInstalledDate(LocalDateTime installedDate) {
			this.installedDate = installedDate;
		}

		public LocalDateTime getCreatedAt() {
			return createdAt;
		}

		public void setCreatedAt(LocalDateTime createdAt) {
			this.createdAt = createdAt;
		}

		
		@Override
		public String toString() {
			return "SoftwareDTO [name=" + name + ", version=" + version + ", vendorName=" + vendorName
					+ ", installedDate=" + installedDate + ", createdAt=" + createdAt + "]";
		}
	

}
