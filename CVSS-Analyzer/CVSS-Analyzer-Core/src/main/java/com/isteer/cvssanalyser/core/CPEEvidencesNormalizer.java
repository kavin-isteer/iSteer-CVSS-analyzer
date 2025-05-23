package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import com.isteer.cvssanalyser.core.dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.DependencyHintModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class CPEEvidencesNormalizer {
	DbUtil dbUtil = new DbUtil();
	DependencyHintDao hintDao = new DependencyHintDao();
	private final Connection connection = dbUtil.getConnection();

	public void normalizeDependencyEvidences(List<DependencyModel> dependencies) {
		if (dependencies == null || dependencies.isEmpty()) {
			return;
		}
		for (DependencyModel dependencyModel : dependencies) {
			String vendor = normalizeVendorEvidences(dependencyModel.getVendorEvidences());
			String product = normalizeProductEvidences(dependencyModel.getProductEvidences());
			String version = normalizeVersionEvidences(dependencyModel.getVersionEvidences());
			if (vendor != null && product != null && version != null) {
				CPENameModel cpe = new CPENameModel();
				cpe.setVendor(vendor);
				cpe.setProduct(product);
				cpe.setVersion(version);
				dependencyModel.setCpeEnumeration(cpe);
			} 
		}
	}

	public String normalizeVendorEvidences(List<Evidence> evidences) {
		String mostLikelyVendor = null;
		List<DependencyHintModel> hints = hintDao.getAllVendorDependencyHints(connection);
		for (Evidence evidence : evidences) {
			if (mostLikelyVendor == null && evidence.getEvidenceType() == EvidenceType.MANIFEST_ENTRY) {
				for (DependencyHintModel hint : hints) {
					if (hint.getEvidenceType().equals("manifest")
							&& evidence.getEvidence().startsWith(hint.getMatch_key())) {
						mostLikelyVendor = hint.getStandardized_name();
						evidence.setResolvedValue(mostLikelyVendor);
					}
				}
			}
			if (mostLikelyVendor == null && evidence.getEvidenceType() == EvidenceType.GROUP_ID) {
				// List<DependencyHintModel> hints =
				// hintDao.getAllVendorDependencyHints(connection,"GAV");
				for (DependencyHintModel hint : hints) {
					if (hint.getEvidenceType().equals("GAV")
							&& evidence.getEvidence().startsWith(hint.getMatch_key())) {
						mostLikelyVendor = hint.getStandardized_name();
						evidence.setResolvedValue(mostLikelyVendor);
					}
				}
			}
		}
		return mostLikelyVendor;
	}

	public String normalizeProductEvidences(List<Evidence> evidences) {
		String mostLikelyProduct = null;
		List<DependencyHintModel> hints = hintDao.getAllProductDependencyHints(connection, "GAV");
		for (Evidence evidence : evidences) {
			if (evidence.getEvidenceType() == EvidenceType.ARTIFACT_ID) {
				for (DependencyHintModel hint : hints) {
					if (evidence.getEvidence().startsWith(hint.getMatch_key())) {
						mostLikelyProduct = hint.getStandardized_name();
						evidence.setResolvedValue(mostLikelyProduct);
						break;
					}
				}
				if (mostLikelyProduct == null) {
					mostLikelyProduct = evidence.getEvidence();
					mostLikelyProduct = mostLikelyProduct.replaceAll("[^a-z0-9_-]", "_");
					mostLikelyProduct = mostLikelyProduct.replace("-", "_");
					evidence.setResolvedValue(mostLikelyProduct);
				}
			}
		}
		return mostLikelyProduct;
	}

	public String normalizeVersionEvidences(List<Evidence> evidences) {
		String mostLikelyVersion = null;
		for (Evidence evidence : evidences) {
			if (evidence.getEvidenceType() == EvidenceType.VERSION) {
				mostLikelyVersion = evidence.getEvidence();
				evidence.setResolvedValue(mostLikelyVersion);
			}
		}
		return mostLikelyVersion;
	}
}
