package com.isteer.cvssanalyser.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class GAVAnalyzer {
	public static void main(String[] args) {
		DependencyTreeResolver treeResolver = new DependencyTreeResolver();
		File projectDir = new File(".");
		List<String> gavs = new ArrayList<>();
		try {
			gavs = treeResolver.fetchDependencies(projectDir);
		} catch (IOException | InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for (String gav : gavs) {
			String[] wrkMavenDependency = gav.split(":");
			if (wrkMavenDependency.length == 5) {
				System.out.println();
				System.out.print("Group Id= "+wrkMavenDependency[0]);
				System.out.print(", Artifact Id= "+wrkMavenDependency[1]);
				System.out.print(", Packaging= "+wrkMavenDependency[2]);
				System.out.print(", Version= "+wrkMavenDependency[3]);
				System.out.print(", Scope= "+wrkMavenDependency[4]);
			} else if (wrkMavenDependency.length == 6) {
				System.out.println();
				System.out.print("Group Id= "+wrkMavenDependency[0]);
				System.out.print(", Artifact Id= "+wrkMavenDependency[1]);
				System.out.print(", Packaging= "+wrkMavenDependency[2]);
				System.out.print(", Version= "+wrkMavenDependency[3]);
				System.out.print(", Scope= "+wrkMavenDependency[5]);
			}
		}
	}
}
