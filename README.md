# ShowPolicyPackage
 
## Background
	The Show Package Tool allows the Security Policy as well as objects in the objects database to be exported 
	into a readable format. This exported information represents a snapshot of the database.

## Output
	The tool generates a compressed file (.tar.gz) containing the following files:

	• HTML files - The objects and rules presented as html files. The "index.html" acts as a starting point and 
	lists all the available items to display.
	
	• JSON files The objects and rules exported as multiple JSON files.
	
	• Log file (e.g. show_package-yyyy-mm-dd_HH-MM-ss.elg) A log file containing debug information.

## Usage Syntax

      $MDS_FWDIR/scripts/web_api_show_package.sh [-d domain-name] [-k package-name] [-n port-number] [-t path] [-o path]
      
      Where:

      • [-d domain-name] (Optional): The name or uid of the Security Management Server domain. When running the command on a Multi
      domain server the default domain is the "MDS".

      • [-k package-name] (Optional): The package name or the uid of the policy package to show.When a package-name is not provided, the
      tool will provide details on all the policy-packages that are being used (the ones that were installed on the security gateways)

      • [-n port-number] (Optional): The port of WebAPI server on Security Management Server.Default value is 443.

      • [-t path] (Optional): The tool uses template files to create HTML pages out of JSON data. This parameter points to the location
      of these files. Default location is $MDS_FWDIR/api/samples/conf/.

      • [-o path] (Optional): The output path. The location in which to save the resulting .tar.gz file. The parameter can also be the
      full path (including the .tar.gz filename). The default is the current directory.

      Use "-h" option in order to see the full list of options to configure the tool

## Examples
	• Running the tool on a Security Management server:
	$MDS_FWDIR/scripts/web_api_show_package.sh

	• Running the tool on a Security Management server for a specific policy package:
	$MDS_FWDIR/scripts/web_api_show_package.sh -k <PACKAGE NAME>

	• Running the tool on a Multi-Domain Server for specific domain and a specific policy package:
	$MDS_FWDIR/scripts/web_api_show_package.sh -k <PACKAGE NAME> -d <DOMAIN NAME>
  
## Instructions

	• Load the sources from "src" folder to a java IDE (Eclipse, IntelliJ IDEA...).

	• In order to build the project, first build [Check Point API Java SDK.](https://github.com/CheckPoint-APIs-Team/cp-mgmt-api-java-sdk) project that will create the “mgmt_api_library_java.jar” in maven local.

	Follow the steps below in order to use the new jar of “Show Package Tool”:

	(BEFORE: Please backup all the original files to have an ability to rollback)

	1.Copy web_api_show_package-jar-with-dependencies.jar from 'jar' directory into $MDS_FWDIR/api/samples/lib
	2.Copy ".template" files  from 'templates' directory into $MDS_FWDIR/api/samples/conf
	3.Copy web_api_show_package.sh  from 'script' directory into $MDS_FWDIR/scripts/

## Note

    This tool is already installed on Check Point Security Management servers running version R80 with Jumbo-HF and above.
