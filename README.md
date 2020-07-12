# ShowPolicyPackage
 
## Background
The Show Package Tool allows the Security Policy as well as objects in the objects database to be exported 
into a readable format. This exported information represents a snapshot of the database.

## Output
The tool generates a compressed file (.tar.gz) containing the following files:

• HTML files - The objects and rules presented as html files. The "index.html" acts as a starting point and  
lists all the available items to display.
	
• JSON files - The objects and rules exported as multiple JSON files.
	
• Log file (e.g. show_package-yyyy-mm-dd_HH-MM-ss.elg) - A log file containing debug information.

## Usage Syntax

To use the tool you have to obtain `web_api_show_package-jar-with-dependencies.jar` artifact by downloading it from the **Releases** tab or by building it from the sources (see **Build Instructions** below).

Then you run:

```java -jar web_api_show_package-jar-with-dependencies.jar [-d domain-name] [-k package-name] [-v] [-c] [-n port-number] [-o path] [--show-membership (true|false)] [--dereference-group-members (true|false)]```
      
Where:

• [-d domain-name] (Optional): The name or uid of the Security Management Server domain.  
When running the command on a Multi domain server the default domain is the "MDS".

• [-v] (Optional): List the existing policy packages.

• [-c] (Optional): Retrieve access policy rules hit counts.

• [-k package-name] (Optional): The package name or the uid of the policy package to show.  
When a package-name is not provided, the tool will provide details on all the policy-packages  
that are being used (the ones that were installed on the security gateways).

• [-n port-number] (Optional): The port of WebAPI server on Security Management Server.  
Default value is 443.

• [-o path] (Optional): The output path. The location in which to save the resulting .tar.gz file.  
The parameter can also be the full path (including the .tar.gz filename).   
The default is the current directory.  

• [--show-membership (true|false)] (Optional): Whether to calculate groups membership for the objects ("groups" field).
This flag is supported from R80.10 Jumbo HF take 70
        
• [--dereference-group-members (true|false)] (Optional): Whether to dereference group members.
This flag is supported from R80.10 Jumbo HF take 70

• [--query-limit limit] (Optional): The objects query limit. No more than that many results will be returned.  
Minimum value is 1, maximum value is 500. Default value is 10.

• [--show-access-policy (true|false)] (Optional): Indicates whether to show access policy as part of policy package. Default value is True.

• [--show-threat-policy (true|false)] (Optional): Indicates whether to show threat policy as part of policy package. Default value is True.

• [--show-nat-policy (true|false)] (Optional): Indicates whether to show nat policy as part of policy package. Default value is True.

Use "--version" option to print the version of the tool

Use "-h" option in order to see the full list of options to configure the tool  

## Examples
• Running the tool on a Security Management server:  
`java -jar web_api_show_package-jar-with-dependencies.jar`  

• Running the tool on a Security Management server for a specific policy package:  
`java -jar web_api_show_package-jar-with-dependencies.jar -k <PACKAGE NAME>`  

• Running the tool on a Multi-Domain Server for specific domain and a specific policy package:  
`java -jar web_api_show_package-jar-with-dependencies.jar -k <PACKAGE NAME> -d <DOMAIN NAME>`  
  
• Running the tool on a side server to list the policy packages from the Security Management server running on 198.51.100.5:  
`java -jar web_api_show_package-jar-with-dependencies.jar -m 198.51.100.5 -v`

## Build Instructions

Follow the steps below in order to build "Show Package Tool" project:   
  
1. build 'java sdk':   
* download directory `cp-mgmt-api-java-sdk-master` from [Check Point API Java SDK](https://github.com/CheckPoint-APIs-Team/cp-mgmt-api-java-sdk)   
* run `mvn clean install`.    
The target directory `cp-mgmt-api-java-sdk-master\mgmt_api_lib\target` should now contain `mgmt_api_library_java-1.0.1.jar`.   
2. build "Show Package Tool":      
* download the 'show package tool' folder .     
* run `mvn clean install`.   
The target directory should now contain `web_api_show_package-jar-with-dependencies.jar`.     
   
Follow the steps below in order to use the new jar of "Show Package Tool" on your Check Point Security Management server:    
  
(BEFORE: Please backup all the original files to have an ability to rollback)  
  
1. Copy `web_api_show_package-jar-with-dependencies.jar` from `target` directory into `$MDS_FWDIR/api/samples/lib`   
2. Copy `web_api_show_package.sh` from `script` directory into `$MDS_FWDIR/scripts/` 

## Note

This tool is already installed on Check Point Security Management servers running version R80 with Jumbo-HF and above.

The Check Point Management Server also has a wrapper script so the tool can be run as `$MDS_FWDIR/scripts/web_api_show_package.sh` which in turn executes `java -jar $MDS_FWDIR/api/samples/lib/web_api_show_package-jar-with-dependencies.jar` 
