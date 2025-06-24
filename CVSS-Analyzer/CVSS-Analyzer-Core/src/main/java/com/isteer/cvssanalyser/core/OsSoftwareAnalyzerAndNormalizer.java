package com.isteer.cvssanalyser.core;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.enums.CpeField;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.enums.ResolveMethod;
import com.isteer.cvssanalyser.core.model.ApplicationModel;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class OsSoftwareAnalyzerAndNormalizer {

	public Map<String, DependencyModel> softwareAnalyzerAndNormalizer(List<ApplicationModel> applications) {
		CveClient cveClient = new CveClient();
		Map<String, DependencyModel> insertedApplications = new HashMap<>();
		for (ApplicationModel application : applications) {
			if (!application.isExists() && application.getApplicationUuid() != null) {
				try {
					DependencyModel resolvedApplication = resolveOsSoftwareNames(application);
					if (resolvedApplication.getCpeEnumeration() != null
							&& resolvedApplication.getCpeEnumeration().getCPE23Uri() != null) {
						cveClient.fetchVulnerabilitiesForDependency(resolvedApplication);
						if (resolvedApplication.getVulnerabilities() != null
								&& resolvedApplication.getVulnerabilities().size() > 0) {
							insertedApplications.put(application.getApplicationUuid(), resolvedApplication);
						}
					}
				} catch (Exception e) {
					// TODO: handle exception
					Engine.logger.error("Error while resolving OS software names for application: "
							+ application.getApplicationName() + " - " + e.getMessage());
				}
			}
		}
		return insertedApplications;
	}

	public DependencyModel resolveOsSoftwareNames(ApplicationModel application) throws SQLException {
		// This method will resolve the OS software names from the list of applications
		// and return a list of DependencyModel objects.
		DependencyHintDao hintDao = new DependencyHintDao();
		DbUtil dbUtil = new DbUtil();
		FuzzySearchTool fuzzySearchTool = new FuzzySearchTool();
		DependencyModel resolvedApplication = new DependencyModel();

		Evidence productEvidence = new Evidence();
		Evidence vendorEvidence = new Evidence();
		Evidence versionEvidence = new Evidence();

		CPENameModel cpe = new CPENameModel();

		String evidenceTitle = "Application-Metadata";

		vendorEvidence.setEvidenceType(EvidenceType.APPLICATION);
		vendorEvidence.setEvidenceTitle(evidenceTitle);
		vendorEvidence.setEvidence(application.getApplicationVendor());

		productEvidence.setEvidenceType(EvidenceType.APPLICATION);
		productEvidence.setEvidenceTitle(evidenceTitle);
		productEvidence.setEvidence(application.getApplicationName());

		versionEvidence.setEvidenceType(EvidenceType.APPLICATION);
		versionEvidence.setEvidenceTitle(evidenceTitle);
		versionEvidence.setEvidence(application.getApplicationVersion());
		versionEvidence.setResolvedValue(application.getApplicationVersion());

		Set<String> resolvedVendor = hintDao.getVendorNameForApplication(dbUtil.getConnection(),
				application.getApplicationVendor());

		if (resolvedVendor != null && !resolvedVendor.isEmpty()) {
			vendorEvidence.setResolvedValue(resolvedVendor.iterator().next());
			cpe.addResolveMethod(CpeField.VENDOR, ResolveMethod.HINT_BY_DEVELOPER);

			List<CpeEntryModel> resolvedProduct = fuzzySearchTool.searchForLikelyProducts(resolvedVendor,
					application.getApplicationName());
			if (resolvedProduct != null && !resolvedProduct.isEmpty()) {
				productEvidence.setResolvedValue(resolvedProduct.get(0).getProduct());
			} else {
				productEvidence.setResolvedValue(null);
			}
		} else {

			CpeEntryModel similarCpe = fuzzySearchTool.searchForCpeEntry(application.getApplicationVendor(),
					application.getApplicationName());
			if (similarCpe == null) {
				vendorEvidence.setResolvedValue(null);
				productEvidence.setResolvedValue(null);
			} else {
				vendorEvidence.setResolvedValue(similarCpe.getVendor());
				productEvidence.setResolvedValue(similarCpe.getProduct());
			}
		}
		if (productEvidence.getResolvedValue() != null && vendorEvidence.getResolvedValue() != null
				&& versionEvidence.getResolvedValue() != null) {
			cpe.setProduct(productEvidence.getResolvedValue());
			cpe.addResolveMethod(CpeField.PRODUCT, ResolveMethod.FUZZY_SEARCH);
			cpe.setVendor(vendorEvidence.getResolvedValue());
			cpe.setVersion(versionEvidence.getResolvedValue());
			cpe.addResolveMethod(CpeField.VERSION, ResolveMethod.ARBITRARY);
		}

		resolvedApplication.addVendorEvidence(vendorEvidence);
		resolvedApplication.addProductEvidences(productEvidence);
		resolvedApplication.addVersionEvidences(versionEvidence);
		resolvedApplication.setCpeEnumeration(cpe);

//		System.out.println(resolvedApplications);
		return resolvedApplication;
	}
}
