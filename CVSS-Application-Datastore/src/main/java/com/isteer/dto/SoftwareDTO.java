package com.isteer.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.isteer.util.CustomLocalDateTimeDeserializer;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public  class SoftwareDTO {
	
	 @NotBlank(message = "Software name cannot be blank")
//        @Size(max = 100, message = "Software name must be at most 100 characters")
        private String name;
        
//        @Size(max = 50, message = "Software version must be at most 50 characters")
        private String version;
        
//        @NotBlank(message = "Vendor name cannot be blank")
//        @Size(max = 100, message = "Vendor name must be at most 100 characters")
        @JsonProperty("VendorName")
        private String vendorName;
        
//        @NotNull(message = "Installed date cannot be null")
//        @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
        @JsonProperty("InstalledDate")
        @JsonDeserialize(using = CustomLocalDateTimeDeserializer.class)
        private LocalDateTime installedDate;
        
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

	

}
