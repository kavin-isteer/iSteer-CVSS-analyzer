package com.isteer.CVSS_Analyzer_Maven_Plugin;


import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Goal which touches a timestamp file.
 */
@Mojo( name = "list-dependencies", defaultPhase = LifecyclePhase.PROCESS_SOURCES )
public class MyMojo
    extends AbstractMojo
{

	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		// TODO Auto-generated method stub
		
	}
}
