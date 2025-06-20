package com.isteer.cvssanalyser.core;

import java.sql.Connection;
import java.util.regex.Pattern;

import com.isteer.cvssanalyser.core.dao.DependencyHintDao;
import com.isteer.cvssanalyser.core.enums.HintAddedBy;
import com.isteer.cvssanalyser.core.model.DependencyHintModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
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
}
