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
	
	 /**
     * Processes a list of dependencies and resolves their vendor, product,
     * and version into a {@link CPENameModel}, if all components are successfully determined.
     *
     * @param dependencies the list of dependencies to normalize
     */
	public void normalizeDependencyEvidences(List<DependencyModel> dependencies) {
		if (dependencies == null || dependencies.isEmpty()) {
			return;
		}
		
		for (DependencyModel dependencyModel : dependencies) {
			//normalize the vendor evidences name from collected evidences and resolve it to a standardized name.
			String vendor = normalizeVendorEvidences(dependencyModel.getVendorEvidences());
			//normalize the product evidences name from collected evidences and resolve it to a standardized name.
			String product = normalizeProductEvidences(dependencyModel.getProductEvidences());
			//normalize the version evidences from collected evidences and resolve it to a standardized name.
			String version = normalizeVersionEvidences(dependencyModel.getVersionEvidences());
			if (vendor != null && product != null && version != null) {
				//create CPE name model from the collected resolved value.
				CPENameModel cpe = new CPENameModel();
				cpe.setVendor(vendor);
				cpe.setProduct(product);
				cpe.setVersion(version);
				dependencyModel.setCpeEnumeration(cpe);
			} 
		}
	}
	
	/**
     * Attempts to normalize vendor evidences based on configured dependency hints.
     * <ul>
     *   <li>First tries matching manifest entries.</li>
     *   <li>If not matched, falls back to group ID evidence.</li>
     * </ul>
     *
     * @param evidences list of vendor evidences (from manifest or GAV)
     * @return the most likely standardized vendor name, or null if not found
     */
	public String normalizeVendorEvidences(List<Evidence> evidences) {
		String mostLikelyVendor = null;
		//get all dependency hints for Vendor from the database.
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
	
	 /**
     * Attempts to normalize product evidences using hints and regex cleanup.
     * <p>
     * If no hints match, it sanitizes the artifact ID to form a default product name.
     * </p>
     *
     * @param evidences list of product evidences (typically from artifactId)
     * @return the most likely standardized product name
     */
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
					mostLikelyProduct = evidence.getEvidence().toLowerCase();
					mostLikelyProduct = mostLikelyProduct.replaceAll("[^a-z0-9_-]", "_");
					mostLikelyProduct = mostLikelyProduct.replace("-", "_");
					evidence.setResolvedValue(mostLikelyProduct);
				}
			}
		}
		return mostLikelyProduct;
	}
	
	/**
     * Extracts the version evidence from the provided list.
     * <p>
     * Assumes the first valid version-type evidence is the correct one.
     * </p>
     *
     * @param evidences list of version evidences
     * @return the detected version string
     */
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
