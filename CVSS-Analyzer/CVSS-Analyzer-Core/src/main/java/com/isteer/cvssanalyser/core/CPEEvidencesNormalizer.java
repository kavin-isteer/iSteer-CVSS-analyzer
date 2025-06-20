package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.isteer.cvssanalyser.core.dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.enums.CpeField;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.enums.HintAddedBy;
import com.isteer.cvssanalyser.core.enums.ResolveMethod;
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
			Map<String,Object> vendor = normalizeVendorEvidences(dependencyModel.getVendorEvidences());
			//normalize the product evidences name from collected evidences and resolve it to a standardized name.
			Map<String,Object> product = normalizeProductEvidences(dependencyModel.getProductEvidences());
			//normalize the version evidences from collected evidences and resolve it to a standardized name.
			Map<String,Object> version = normalizeVersionEvidences(dependencyModel.getVersionEvidences());
			if (vendor.get("value") != null && product.get("value") != null && version.get("value") != null) {
				//create CPE name model from the collected resolved value.
				CPENameModel cpe = new CPENameModel();
				cpe.setVendor((String)vendor.get("value"));
				cpe.addResolveMethod(CpeField.VENDOR,(ResolveMethod)vendor.get("resolveMethod"));
				cpe.setProduct((String)product.get("value"));
				cpe.addResolveMethod(CpeField.PRODUCT,(ResolveMethod)product.get("resolveMethod"));
				cpe.setVersion((String)version.get("value"));
				cpe.addResolveMethod(CpeField.VERSION,(ResolveMethod)version.get("resolveMethod"));
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
     * @return Map of 2 entries. First one will be the most likely standardized vendor name and second one will be the resolve method of the vendor name.
     */
	public Map<String, Object> normalizeVendorEvidences(List<Evidence> evidences) {
		String mostLikelyVendor = null;
		ResolveMethod resolveMethod=null;
		Map<String, Object> resolvedValue = new HashMap<>();
		//get all dependency hints for Vendor from the database.
		List<DependencyHintModel> hints = hintDao.getAllVendorDependencyHints(connection);
		for (Evidence evidence : evidences) {
			if (mostLikelyVendor == null && evidence.getEvidenceType() == EvidenceType.MANIFEST_ENTRY) {
				for (DependencyHintModel hint : hints) {
					if (hint.getEvidenceType().equals("manifest")
							&& evidence.getEvidence().startsWith(hint.getMatch_key())) {
						mostLikelyVendor = hint.getStandardized_name();
						evidence.setResolvedValue(mostLikelyVendor);
						if(hint.getAddedBy()==HintAddedBy.CLIENT_USER) {
							resolveMethod=ResolveMethod.HINT_BY_CLIENT_USER;
						}else if(hint.getAddedBy()==HintAddedBy.DEVELOPER) {
							resolveMethod=ResolveMethod.HINT_BY_DEVELOPER;
						}
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
						if(hint.getAddedBy()==HintAddedBy.CLIENT_USER) {
							resolveMethod=ResolveMethod.HINT_BY_CLIENT_USER;
						}else if(hint.getAddedBy()==HintAddedBy.DEVELOPER) {
							resolveMethod=ResolveMethod.HINT_BY_DEVELOPER;
						}
					}
				}
			}
		}
		resolvedValue.put("value", mostLikelyVendor);
		resolvedValue.put("resolveMethod", resolveMethod);
		return resolvedValue;
	}
	
	 /**
     * Attempts to normalize product evidences using hints and regex cleanup.
     * <p>
     * If no hints match, it sanitizes the artifact ID to form a default product name.
     * </p>
     *
     * @param evidences list of product evidences (typically from artifactId)
     * @return Map of 2 entries. First one will be the most likely standardized product name and second one will be the resolve method of the product name.
     */
	public Map<String, Object> normalizeProductEvidences(List<Evidence> evidences) {
		String mostLikelyProduct = null;
		ResolveMethod resolveMethod=null;
		Map<String, Object> resolvedValue = new HashMap<>();
		List<DependencyHintModel> hints = hintDao.getAllProductDependencyHints(connection, "GAV");
		for (Evidence evidence : evidences) {
			if (evidence.getEvidenceType() == EvidenceType.ARTIFACT_ID) {
				for (DependencyHintModel hint : hints) {
					if (evidence.getEvidence().startsWith(hint.getMatch_key())) {
						mostLikelyProduct = hint.getStandardized_name();
						evidence.setResolvedValue(mostLikelyProduct);
						if(hint.getAddedBy()==HintAddedBy.CLIENT_USER) {
							resolveMethod=ResolveMethod.HINT_BY_CLIENT_USER;
						}else if(hint.getAddedBy()==HintAddedBy.DEVELOPER) {
							resolveMethod=ResolveMethod.HINT_BY_DEVELOPER;
						}
						break;
					}
				}
				if (mostLikelyProduct == null) {
					mostLikelyProduct = evidence.getEvidence().toLowerCase();
					mostLikelyProduct = mostLikelyProduct.replaceAll("[^a-z0-9_-]", "_");
					mostLikelyProduct = mostLikelyProduct.replace("-", "_");
					evidence.setResolvedValue(mostLikelyProduct);
					resolveMethod=ResolveMethod.ARBITRARY;
				}
			}
		}
		resolvedValue.put("value", mostLikelyProduct);
		resolvedValue.put("resolveMethod", resolveMethod);
		return resolvedValue;
	}
	
	/**
     * Extracts the version evidence from the provided list.
     * <p>
     * Assumes the first valid version-type evidence is the correct one.
     * </p>
     *
     * @param evidences list of version evidences
     * @return Map of 2 entries. First one will be the detected version and second one will be the resolve method of the version.
     */
	public Map<String, Object> normalizeVersionEvidences(List<Evidence> evidences) {
		String mostLikelyVersion = null;
		ResolveMethod resolveMethod=null;
		Map<String, Object> resolvedValue = new HashMap<>();
		for (Evidence evidence : evidences) {
			if (evidence.getEvidenceType() == EvidenceType.VERSION) {
				mostLikelyVersion = evidence.getEvidence();
				evidence.setResolvedValue(mostLikelyVersion);
				resolveMethod=ResolveMethod.ARBITRARY;
			}
		}
		resolvedValue.put("value", mostLikelyVersion);
		resolvedValue.put("resolveMethod", resolveMethod);
		return resolvedValue;
	}
}
