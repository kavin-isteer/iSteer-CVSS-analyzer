package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.util.List;
import java.util.regex.Pattern;

import com.isteer.cvssanalyser.core.dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.dto.DependencyHintDto;
import com.isteer.cvssanalyser.core.enums.EvidenceType;
import com.isteer.cvssanalyser.core.enums.HintAddedBy;
import com.isteer.cvssanalyser.core.model.DependencyHintModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.Evidence;
import com.isteer.cvssanalyser.core.util.DbUtil;

public class DependencyHintService {
	DbUtil dbUtil = new DbUtil();
	DependencyHintDao hintDao = new DependencyHintDao();
	private final Connection connection = dbUtil.getConnection();

	/**
	 * @param cpeName
	 * @param dependency
	 * @return
	 */
	//FIXME: add javadoc here
	public int addGAVDependencyHint(String cpeName, DependencyModel dependency) {
		if (!isValidCPE(cpeName)) { 
			return -1;
		}
		DependencyHintModel hintToSave = new DependencyHintModel();
		String[] cpeNameStripped = cpeName.split(":");
		String vendor = cpeNameStripped[3];
		String product = cpeNameStripped[4];
	//	String version = cpeNameStripped[5];

		String GAV = dependency.getDependencyName();
		String[] GavLiterals = GAV.split(":");
		String groupId = GavLiterals[0];
		String artifactId = GavLiterals[1];
	//	String gavVersion = GavLiterals[3];

		hintToSave.setType("vendor");
		hintToSave.setMatch_key(groupId);
		hintToSave.setStandardized_name(vendor);
		hintToSave.setConfidence("HIGH");
		hintToSave.setDescription("Hint added through add hint api!");
		hintToSave.setEvidenceType("GAV");
		hintToSave.setAddedBy(HintAddedBy.CLIENT_USER);
		int rows = hintDao.addDependencyHint(connection, hintToSave);
		if(rows>0) {
			hintToSave.setType("product");
			hintToSave.setMatch_key(artifactId);
			hintToSave.setStandardized_name(product);
			hintToSave.setConfidence("HIGH");
			hintToSave.setDescription("Hint added through add hint api!");
			hintToSave.setEvidenceType("GAV");
			hintToSave.setAddedBy(HintAddedBy.CLIENT_USER);
			rows = hintDao.addDependencyHint(connection, hintToSave);
			if(rows>0) {
				return 1;
			}
			else {
				return -2;
			}
		}else {
			return -3;
		}
	}
	// Regular expression to match CPE 2.3 format
	private static final Pattern CPE_2_3_PATTERN = Pattern.compile("^cpe:2\\.3:[aho](:[^:]*){10}$");

	/**
	 * Validates if the given string is a valid CPE 2.3 formatted name.
	 *
	 * @param cpe the CPE name string to validate
	 * @return true if the string is a valid CPE 2.3 name; false otherwise
	 */
	public static boolean isValidCPE(String cpe) {
		if (cpe == null) {
			return false;
		}
		return CPE_2_3_PATTERN.matcher(cpe).matches();
	}
	
	//FIXME: add javadoc here
	public int addManifestDependencyHint( DependencyHintDto hintDto) {
		if (!isValidCPE(hintDto.getCpeName())) { 
			return -1;
		}
		if(hintDto.getMatchKey()==null || hintDto.getMatchKey().isEmpty()) {
			//Improper payload
			return -5;
		}
		String[] cpeNameStripped = hintDto.getCpeName().split(":");
		String vendor = cpeNameStripped[3];
		String product = cpeNameStripped[4];
	//	String version = cpeNameStripped[5];
		
		DependencyHintModel hintToSave = new DependencyHintModel();
		if(hintDto.getHintType().equals("vendor")) {
			if(!hintDto.getStandardizedName().equals(vendor)) {
				//vendor standardised name does not match with provided CPE name.
				return -3;
			}
			hintToSave.setType("vendor");
			hintToSave.setMatch_key(hintDto.getMatchKey());
			hintToSave.setStandardized_name(vendor);
			hintToSave.setConfidence("HIGH");
			hintToSave.setDescription("Hint added through add hint api!");
			hintToSave.setEvidenceType("manifest");
			hintToSave.setAddedBy(HintAddedBy.CLIENT_USER);
			int rows = hintDao.addDependencyHint(connection, hintToSave);
			if(rows>0) {
				return 1;
			}
		}else if(hintDto.getHintType().equals("product")) {
			if(!hintDto.getStandardizedName().equals(product)) {
				//product standardised name does not match with provided CPE name.
				return -4;
			}
			hintToSave.setType("product");
			hintToSave.setMatch_key(hintDto.getMatchKey());
			hintToSave.setStandardized_name(product);
			hintToSave.setConfidence("HIGH");
			hintToSave.setDescription("Hint added through add hint api!");
			hintToSave.setEvidenceType("manifest");
			hintToSave.setAddedBy(HintAddedBy.CLIENT_USER);
			int rows = hintDao.addDependencyHint(connection, hintToSave);
			if(rows>0) {
				return 1;
			}
		}else {
			//hint type not valid
			return -2;
		}
		//Unknown error. Hint not saved.
		return -6;
	}
}
