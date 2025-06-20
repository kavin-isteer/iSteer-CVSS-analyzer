package com.isteer.cvssanalyser.core;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.isteer.cvssanalyser.core.dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.ApplicationModel;
import com.isteer.cvssanalyser.core.model.CpeEntryModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class OsSoftwareAnalyzer {

	public List<DependencyModel> resolveOsSoftwareNames(ApplicationModel application) throws SQLException {
		// This method will resolve the OS software names from the list of applications
		// and return a list of DependencyModel objects.
		DependencyHintDao hintDao = new DependencyHintDao();
		DbUtil dbUtil = new DbUtil();
		FuzzySearchTool fuzzySearchTool = new FuzzySearchTool();
		List<DependencyModel> resolvedApplications = new ArrayList<>();
		DependencyModel dependency = new DependencyModel();
		Evidence productEvidence = new Evidence();
		Evidence vendorEvidence = new Evidence();
		Evidence versionEvidence = new Evidence();
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
			List<CpeEntryModel> resolvedProduct = fuzzySearchTool.searchForLikelyProducts(resolvedVendor,
					application.getApplicationName());
			if (resolvedProduct != null && !resolvedProduct.isEmpty()) {
				vendorEvidence.setResolvedValue(resolvedProduct.get(0).getVendor());
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
		dependency.addVendorEvidence(vendorEvidence);
		dependency.addProductEvidences(productEvidence);
		dependency.addVersionEvidences(versionEvidence);

		resolvedApplications.add(dependency);
		return resolvedApplications;
	}
}
