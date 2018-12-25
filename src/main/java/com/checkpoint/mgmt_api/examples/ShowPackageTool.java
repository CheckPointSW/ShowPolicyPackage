/*
 * Copyright © 2016 Check Point Software Technologies Ltd.  All Rights Reserved.
 * Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee and without a signed licensing agreement, is hereby
 * granted, provided that the above copyright notice, this paragraph and the following three paragraphs appear in all copies, modifications, and distributions.
 * <p/>
 * CHECK POINT DOES NOT PROVIDE, AND HAS NO OBLIGATION TO PROVIDE, MAINTENANCE SERVICES, TECHNICAL OR CUSTOMER SUPPORT, UPDATES,
 * ENHANCEMENTS, OR MODIFICATIONS FOR THE SOFTWARE OR THE DOCUMENTATION.
 * <p/>
 * TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE SOFTWARE AND DOCUMENTATION IS PROVIDED ON AN "AS IS," "AS AVAILABLE" AND "WHERE-IS"
 * BASIS.  ALL CONDITIONS, REPRESENTATIONS AND WARRANTIES WITH RESPECT TO THE SOFTWARE OR ITS DOCUMENTATION, WHETHER EXPRESS, IMPLIED, STATUTORY
 * OR OTHERWISE, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT OF THIRD PARTY
 * RIGHTS, ARE HEREBY DISCLAIMED.
 * <p/>
 * IN NO EVENT SHALL CHECK POINT BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF CHECK POINT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.checkpoint.mgmt_api.examples;

import com.checkpoint.mgmt_api.client.*;
import com.checkpoint.mgmt_api.objects.*;
import com.checkpoint.mgmt_api.utils.TarGZUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Handler;

/**
 * This class creates html pages that show the rulbases, layers and objects that are part of packages whose policy
 * is installed on gateways (or a specific package if passed as an argument by the user).
 * If the management server contains only one package, this package will be shown
 */
public class ShowPackageTool {

    static {
        final String HTTPS_PROTOCOLS_PROPERTY = "https.protocols";

        if (System.getProperty(HTTPS_PROTOCOLS_PROPERTY) == null) {
            System.setProperty(HTTPS_PROTOCOLS_PROPERTY, "TLSv1,TLSv1.1,TLSv1.2");
        }
    }

    private static ShowPackageConfiguration configuration = ShowPackageConfiguration.INSTANCE;
    private static ApiClient client;
    private static ApiLoginResponse loginResponse;
    private static JSONObject allTypes = null;

    private static final int NUMBER_OF_EXECUTORS = 2;

    private static final String TYPE      = "type";
    private static final String UNDEFINED = "undefined";

    //Types of rules
    private static String[] accessTypes = {"access-section", "access-rule", "place-holder"};
    private static String[] natTypes    = {"nat-section", "nat-rule", "place-holder"};
    private static String[] threatTypes = {"threat-section", "threat-exception", "place-holder"};

    // Object fields that contains nested objects
    private static final String[] OBJECT_FIELDS_CONTAINING_NESTED_OBJECTS = {"except", "include", "location"};
    private static final String[] COLLECTION_FIELDS_CONTAINING_NESTED_OBJECTS = {"members", "networks"};

    private enum RulebaseType {

        ACCESS ("access"),
        NAT ("nat"),
        THREAT ("threat-prevention");

        private final String name;

        RulebaseType(String s) {
            name = s;
        }
        private String typeToString() {
            return this.name;
        }
    }

    private enum MessageType {

        INFO ,
        SEVERE ,
        WARNING,
        EXIT_WITHOUT_MESSAGE
    }


    public static void main(String[] args) {

        /*Initialize arguments for the tool*/
        try {
            configuration.initializeParameters(args);
        }
        catch (Exception e) {
            logoutReportAndExit(e.getMessage() != null ? e.getMessage() : e.getClass().getName(), MessageType.SEVERE, false);
        }

        /*Prepare Api client settings*/
        ApiClientArgs apiClientArgs = new ApiClientArgs();

        /*If the connection is through a proxy, configure ApiClientArgs to use proxy settings*/
        String proxy = configuration.getProxy();
        if(proxy != null && !proxy.isEmpty()){
            apiClientArgs.setProxySetting(proxy);
        }

        /*If the user asked for a certain port, then set the port to a given port*/
        if(configuration.isUserEnteredPort()){
            apiClientArgs.setPort(configuration.getPort());
        }

        if(configuration.isUnsafe()){
            apiClientArgs.setCheckFingerprint(false);
        }

        /*Create an Api client and verify the server's fingerprint*/
        client = new ApiClient(apiClientArgs);
        client.setLimitQuery(configuration.getQueryLimit());

        configuration.getLogger().debug("Limit number of object per page: " + configuration.getQueryLimit());

        /*Check if the connection is to the local server*/
        boolean loginAsRoot = isLoginAsRoot();

        if(!configuration.isUnsafe()) {
            verifyServerFingerprint(loginAsRoot);
        }
        configuration.getLogger().debug("Login As root: " + loginAsRoot);

        /*Login to the Check Point Management server*/
        if (!loginAsRoot) {
            try {
                loginResponse = client.login(configuration.getServer(), configuration.createPayloadForLogin(false));
            }
            catch (ApiClientException e) {
                logoutReportAndExit("An error occurred while logging in to the server. Exception: "+ e.getMessage(), MessageType.SEVERE);
            }
        }
        else {
            //Login as root
            try {
                loginResponse = client.loginAsRoot(configuration.createPayloadForLogin(true));
            }catch (ApiClientRunTimeException e){
                logoutReportAndExit("An error occurred while logging in to the server "+ e.getMessage(), MessageType.SEVERE);
            }
        }
        if(loginResponse == null){
            logoutReportAndExit("An error occurred while logging in to the server", MessageType.SEVERE);
        }
        else if(!loginResponse.isSuccess()){
            logoutReportAndExit("An error occurred while logging in to the server. "
                                  + errorResponseToString(loginResponse) , MessageType.SEVERE);
        }

        writeTheVersionsToTheLogger();

        configuration.getLogger().debug("Chosen server IP: " + loginResponse.getServerIP());
        configuration.getLogger().debug("Login response: " + loginResponse.getPayload());

        IndexView index = new IndexView();

        handlePublishedSession(index);

         /*Update the index page data*/
        index.setDomain(configuration.getDomain());

        /*Show all gateways and servers*/
        collectGatewaysInUseAndInstalledPolicies();

        JSONArray objectsCollection = showVpnCommunities();

        /*Prepare the packages for show*/
        showPackages(index, objectsCollection);

        /*Build the index page and create the tar file*/
        buildIndexHtmlPage(index);

        /*Create tar file, free the handlers and deletes temps files */
        logoutReportAndExit("", MessageType.EXIT_WITHOUT_MESSAGE);
    }

    private static void handlePublishedSession(IndexView index)
    {
        Session session = new Session();
        JSONObject sessionPayload = new JSONObject();
        ApiResponse sessionRes = null;

        //get last published session
        try {
            sessionRes = client.apiCall(loginResponse, "show-last-published-session", "{}");
        }
        catch (ApiClientException e) {
            logoutReportAndExit("Failed to show last published session. Exception: "+ e.getMessage(), MessageType.SEVERE);
        }
        if (sessionRes == null || !sessionRes.isSuccess()) {
            //print error: if client asked to switch session in management with no published sessions
            if (configuration.getPublishedSessionUid() != null) {
                logoutReportAndExit(errorResponseToString(
                        sessionRes) + " - could not switch to the required session: " + configuration.getPublishedSessionUid(),
                                    MessageType.SEVERE);
            }
            //print info: no published sessions in the management
            else {
                configuration.getLogger().info(errorResponseToString(sessionRes));
            }
        }
        else {
            //check if the given id is the last published session and set uid
            if (configuration.getPublishedSessionUid() != null) {
                session.setUid(configuration.getPublishedSessionUid());

                if (sessionRes.getPayload().get("uid").toString().equals(configuration.getPublishedSessionUid())) {
                    session.setLastPublishedSession(true);
                }
                else {
                    session.setLastPublishedSession(false);
                }
            }
            else {
                session.setUid(sessionRes.getPayload().get("uid").toString());
                session.setLastPublishedSession(true);
            }

            //if not the last published session - get the published session
            if (!session.getLastPublishedSession()) {
                sessionPayload.put("uid", session.getUid());
                try {
                    sessionRes = client.apiCall(loginResponse, "show-session", sessionPayload);
                }
                catch (ApiClientException e) {
                    logoutReportAndExit(
                            "Failed to show the session" + session.getUid() + ". Exception: " + e.getMessage(),
                            MessageType.SEVERE);
                }
                if (sessionRes == null || !sessionRes.isSuccess()) {
                    logoutReportAndExit(
                            "Failed to show the session" + session.getUid() + ". Exception: " + errorResponseToString(
                                    sessionRes), MessageType.SEVERE);
                }
            }

            //get name and published time of the published session
            Object sessionName = sessionRes.getPayload().get("name");
            Object publishTime = sessionRes.getPayload().get("publish-time");

            if(sessionName != null)
                session.setName(sessionName.toString());
            else
                session.setName("");

            if(publishTime != null)
                session.setPublishTime(((HashMap)publishTime).get("iso-8601").toString());
            else
                logoutReportAndExit("Input published session is not published - ", MessageType.SEVERE);

            //Switching to published session
            ApiResponse switchSessionRes = null;
            if (configuration.getPublishedSessionUid() != null) {
                sessionPayload.clear();
                sessionPayload.put("uid", session.getUid());
                try {
                    switchSessionRes = client.apiCall(loginResponse, "switch-session", sessionPayload);
                }
                catch (ApiClientException e) {
                    logoutReportAndExit(
                            "An error occurred while switching to the input published session. Exception: " + e.getMessage(),
                            MessageType.SEVERE);
                }
                if (switchSessionRes == null || !switchSessionRes.isSuccess()) {
                    logoutReportAndExit(
                            "Failed to switch published session uid " + configuration.getPublishedSessionUid() + ". " + errorResponseToString(
                                    switchSessionRes), MessageType.SEVERE);
                }
            }
            index.setSession(session);
        }

    }

    /**
     * This function check if to login as root or with user name and password
     * @return True if the login is as root
     */
    private static boolean isLoginAsRoot(){

        /*Check if the user entered use name and password*/
        if (configuration.getUsername() != null && configuration.getPassword() != null){
            return false;
        }

        /*Check if the connection is to the local server*/
        List<String> localIps = getLocalIps();
        configuration.getLogger().debug("Local Ips: " + Arrays.toString(localIps.toArray()));

        return localIps.contains(configuration.getServer());
    }

    private static void verifyServerFingerprint(boolean loginAsRoot){
        String server;
        if (loginAsRoot){
            server = ApiClient.LOCAL_SERVER_IP;
        }
        else{
            server = configuration.getServer();
        }
        try {
            if (configuration.isUserEnteredPort()) {
                UtilClass.verifyServerFingerprint(client, loginAsRoot, server, configuration.getPort());
            }
            else {
                UtilClass.verifyServerFingerprint(client, loginAsRoot, server);
            }
        }catch (ApiClientException e){
            logoutReportAndExit(e.getMessage(), MessageType.SEVERE);
        }
    }

    /**
     * This function write the Api version and the tool version into the log file
     */
    private static void writeTheVersionsToTheLogger() {

        /*Set web Api version and look for the api-server-version, if it does not exist, that means we are in the
         webApiVersion v1.0 (Hero GA).*/

        if (loginResponse.getApiVersion() == null) {
            configuration.getLogger().info("api-server-webApiVersion does not exist, assuming v1.0 (Hero GA)");
        }
        else {
            String webApiVersion = loginResponse.getApiVersion();
            configuration.getLogger().info("Management API running version: " + webApiVersion);
        }

        //Set the tool version
        configuration.getLogger().info("show_package " + configuration.getToolVersion());
        configuration.getLogger().info("Chosen port: " + loginResponse.getPort());
    }

    /**
     * This function collects all the gateways and servers that exist on the management server
     */
    private static void collectGatewaysInUseAndInstalledPolicies()
    {

        ApiResponse res = null;
        try {
            configuration.getLogger().debug("Run command: 'show-gateways-and-servers' with details level 'full'");
            res = client.apiQuery(loginResponse, "show-gateways-and-servers", "objects", "{\"details-level\" : \"full\"}");
        }
        catch (ApiClientException e) {
            logoutReportAndExit("Failed to run gateways-and-servers command." + e.getMessage(), MessageType.SEVERE);
        }
        if (res == null || !res.isSuccess()) {
            logoutReportAndExit("Failed to run gateways-and-servers command. " + errorResponseToString(res), MessageType.SEVERE);
        }

        if (!res.getPayload().containsKey("objects")) {
            configuration.getLogger().debug("'objects' key doesn't exist in response from" +
                    " 'show-gateways-and-servers' command");
            return;
        }
        JSONArray allGatewaysAndServers = (JSONArray) res.getPayload().get("objects");

        int numberOfObjects = allGatewaysAndServers.size();
        configuration.getLogger().debug("Found " + numberOfObjects + " gateways from 'show-gateways-and-servers' ");

        //pass over all the gateways and servers
        for (Object gatewayOrServer : allGatewaysAndServers) {
            JSONObject gatewayOrServerJson = (JSONObject) gatewayOrServer;
            //If a policy is installed on the gateway, add this gateway to the list
            if (gatewayOrServerJson.containsKey("policy")) {
                JSONObject policy = (JSONObject) gatewayOrServerJson.get("policy");
                if (!policy.isEmpty()) {
                    GatewayAndServer gateway = buildNewGatewayOrServer(gatewayOrServerJson);
                    configuration.setGatewaysWithPolicy(gateway);
                }
            }
        }
        int numberOfObjectsWithPolicies = configuration.getGatewaysWithPolicy().size();
        configuration.getLogger().info("Found " + numberOfObjectsWithPolicies +
                " gateways that have a policy installed on them");

    }

    /**
     * This function collects all the vpn communities which exist on the management server
     *
     * @return the object collection
     */
    private static JSONArray showVpnCommunities() {

        ApiResponse res;
        JSONArray objectsInUse = new JSONArray();
        List<String> commands = new ArrayList<>();
        commands.add("show-vpn-communities-star");
        commands.add("show-vpn-communities-meshed");

        for (String command : commands) {
            try {
                configuration.getLogger().debug("Run command: '" + command + "' with details level 'full'");
                res = client.apiQuery(loginResponse,command, "objects", "{\"details-level\" : \"full\"}");
            }
            catch (ApiClientException e) {
                configuration.getLogger().warning("Failed to execute command: " +command + ". Exception: " + e.getMessage());
                continue;
            }
            if(res == null || !res.isSuccess() ) {
                configuration.getLogger().warning("Failed to execute command: " +command + ". " + errorResponseToString(res));
                continue;
            }
            JSONArray allVpnCommunities = (JSONArray)res.getPayload().get("objects");

            objectsInUse.addAll(allVpnCommunities);
        }

        int numberObjectsInUse = objectsInUse.size();
        configuration.getLogger().debug("Found " +numberObjectsInUse + " vpn communities");

        return objectsInUse;
    }

    /**
     *  This function selects which package to show, and collects all the relevant information.
     *
     * @param index the index object
     * @param objectsInUse the objects that the packages contain
     */
    private static void showPackages(IndexView index, JSONArray objectsInUse){

        PolicyPackage policy;

        if(configuration.getUserRequestPackage() == null || configuration.getUserRequestPackage().isEmpty() ||
                configuration.showPackagesList()) {

            //Show all the packages that exist on the server
            List<String> allExistsPackages = getAllPackages();

            //Checks if the flag -v (show the packages) is set to True,
            if(configuration.showPackagesList()){
                printTheExistingPackagesAndExit(allExistsPackages);
            }

            if ( allExistsPackages.isEmpty()) {
                logoutReportAndExit("No packages found on the server. Try to login to a user's domain", MessageType.WARNING);
            }

            configuration.getLogger().info("Packages which were found on the management: " + allExistsPackages.toString());
            configuration.getLogger().info("Packages which were installed on gateways: " + configuration.getInstalledPackages().toString());

            if (allExistsPackages.size() > 1) {

                //Check whether there are packages which were installed on a gateway
                if( configuration.getInstalledPackages().isEmpty() ){
                    System.out.println("More than one package exists but neither one of them is installed on a gateway.\n" +
                            "In order to show a specific package, run with -k [package name].\n"+
                            "In order to show all the existing packages, run with -v\n");

                    return;
                }

                configuration.getLogger().info("More then one package exists," +
                        " show all packages that are installed on a gateway");
                //More then one package exists, show all packages that are installed on a gateway
                for (String packageName : configuration.getInstalledPackages()) {
                    policy = buildPackagePolicy(packageName, objectsInUse);
                    if (policy != null) {
                        index.getPolicyPackages().add(policy);
                    }
                }
            }
            else {
                configuration.getLogger().info("Only one package exists, show this package: '" + allExistsPackages.get(0) + "'");
                //Only one package exists, show this package
                String packageName = allExistsPackages.get(0);
                policy = buildPackagePolicy(packageName, objectsInUse);
                if (policy != null) {
                    index.getPolicyPackages().add(policy);
                }
            }
        }
        else{
            configuration.getLogger().info("Show only a specific package (the one that was entered as an argument): '"
                    + configuration.getUserRequestPackage() + "'");
            //Show only a specific package (the one that was entered as an argument)
            policy = buildPackagePolicy(configuration.getUserRequestPackage(), objectsInUse);
            if (policy != null) {
                index.getPolicyPackages().add(policy);
            }
        }
    }

    /**
     *This function returns a list of all the packages that exist on the Check Point Management Server
     *
     * @return List of all the packages that exists on the Check Point Management Server
     */
    private static List<String> getAllPackages() {
        List<String> packagesName = new ArrayList<>();
        ApiResponse res           = null;

        //Get all existing packages
        try {
            configuration.getLogger().debug("Run command: 'show-packages' with details level 'full'");
            res = client.apiQuery(loginResponse,"show-packages","packages", "{\"details-level\" : \"full\"}");

        }//In case of an error
        catch (ApiClientException e) {
            logoutReportAndExit("Failed to run show-packages command. Aborting. " + e.getMessage(), MessageType.SEVERE);
        }
        if (res == null || !res.isSuccess()) {
            logoutReportAndExit("Failed to run show-packages command. Aborting. " + errorResponseToString(res), MessageType.SEVERE);
        }
        else {
            //There are packages
            JSONArray packages = (JSONArray) res.getPayload().get("packages");
            configuration.getLogger().debug("Found " + packages.size() + " packages");

            for (Object packageObject : packages) {
                //Add the name of the package to the list
                packagesName.add(((JSONObject) packageObject).get("name").toString());
            }
        }
        return packagesName;
    }

    /**
     * This function prints the names of all the existing packages.
     *
     * @param allPackages list all of the existence packages
     */
    private static void printTheExistingPackagesAndExit(List<String> allPackages){
        //Need to print the package names
        System.out.println("\npackages:");
        for (String packageName : allPackages){
            System.out.println(packageName);
        }
        System.out.println();
        logoutReportAndExit(null, MessageType.EXIT_WITHOUT_MESSAGE);
    }

    /**
     * This function collects information (layers and objects) about a given package.
     *
     * @param packageName the package name to collect the information about.
     * @param objectsInUse the objects that were already collected
     *
     * @return {@link PolicyPackage} contains information about the package
     */
    private static PolicyPackage buildPackagePolicy(String packageName, JSONArray objectsInUse) {

        List<Layer> accessLayers = new ArrayList<>();
        List<Layer> threatLayers = new ArrayList<>();
        Layer natLayer;
        PolicyPackage policyPackage = null;
        try {
            //The vpn communities which were collected are common to all of the policy packages.
            //Clone these objects in order to include the vpn communities in all the packages.
            addObjectsInfoIntoCollections(objectsInUse);

            //Fill the layer and the layer's list with information about the package's layers.
            configuration.getLogger().debug("Starting to process layers of package '" + packageName + "'");

            natLayer = aggregatePackageLayers(packageName, accessLayers, threatLayers);
            //Handle access layer
            configuration.getLogger().debug("Handle access layers");
            for (Layer accessLayer : accessLayers) {
                showAccessRulebase(accessLayer, packageName);
            }

            //Handle nat layer
            if (natLayer != null) {
                configuration.getLogger().debug("Handle nat layer");
                showNatRulebase(natLayer, packageName);
            }

            //Handle threat layers
            configuration.getLogger().debug("Handle threat layers");
            for (Layer threatLayer : threatLayers) {
                showThreatRulebase(packageName, threatLayer);
            }

            final Queue<String> objectsQueue = configuration.getNestedObjectsToRetrieve();
            configuration.getLogger().info("There are " + objectsQueue.size() + " nested object(s) to retrieve (with limit " + configuration.getQueryLimit() + ")");
            while (!objectsQueue.isEmpty()) {

                final Set<String> objectsToRetrieveChunk = new LinkedHashSet<>();
                String uidFromQueue;
                while (objectsToRetrieveChunk.size() < configuration.getQueryLimit() && (uidFromQueue = objectsQueue.poll()) != null) {
                    objectsToRetrieveChunk.add(uidFromQueue);
                }

                JSONObject payload = new JSONObject();

                payload.put("limit", configuration.getQueryLimit());
                payload.put("details-level", "full");

                addNewFlagsToControlDetailsLevel(payload);

                final JSONArray objectsFilter = new JSONArray();
                objectsFilter.add("objId");
                objectsFilter.addAll(objectsToRetrieveChunk);

                payload.put("in", objectsFilter);

                try {
                    ApiResponse res = client.apiCall(loginResponse, "show-objects", payload);
                    addObjectsInfoIntoCollections((JSONArray) res.getPayload().get("objects"));

                    List<String> missingUids = new ArrayList<>();
                    for (String uid : objectsToRetrieveChunk) {
                        if (!configuration.getUidToName().containsKey(uid)) {
                            missingUids.add(uid);
                        }
                    }

                    configuration.getLogger().info(res.getPayload().get("total") + " objects were retrieved. New size of nested objects queue is " + objectsQueue.size());
                    if (!missingUids.isEmpty()) {
                        configuration.getLogger().info("There are " + missingUids.size() + " failed / non-object uid(s) " + missingUids.toString());
                    }
                }
                catch (ApiClientException e) {
                    handleException(e, "Failed to run show-objects");
                }
            }


            //Crete a Html page that contains the objects of the package
            writeDictionary(packageName);

            //Create a policy package
            policyPackage = new PolicyPackage(packageName, accessLayers, threatLayers, natLayer, allTypes);

            //Handle gateways that the policy is install on
            JSONArray gatewayObjects = new JSONArray();
            for (GatewayAndServer gateway : configuration.getGatewaysWithPolicy()) {
                //Add all the relevant gateways and servers for the current package
                if (gateway.getAccessPolicy() != null && packageName.equalsIgnoreCase(gateway.getAccessPolicy()) ||
                        gateway.getThreatPolicy() != null && packageName.equalsIgnoreCase(gateway.getThreatPolicy())) {
                    gatewayObjects.add(gateway.getGatewayObject());
                    policyPackage.setGatewayAndServer(gateway);
                }
            }

            //Create a html page that contains the gateways
            if (!gatewayObjects.isEmpty()) {
                writeGateways(packageName, gatewayObjects);
            }
        }
        catch (Exception e){

            handleException(e, "Error: failed while creating policy package: '" + packageName + "'. Exception: " + e.getMessage());
        }
        finally {
            // initialize it for he next package
            allTypes = null;
            configuration.getUidToName().clear();
        }
        return policyPackage;
    }

    /**
     * This function sets the access and threat layers list and the nat layer according to the layers
     * which exist
     *
     * on the given package
     *
     * @param packageName package name
     * @param accessLayers list of access layers that the function fills
     * @param threatLayers list of threat layers that the function fills
     *
     * @return natLayer nat layer that the function sets
     */
    private static Layer aggregatePackageLayers(String packageName, List<Layer> accessLayers,
                                                List<Layer> threatLayers){
        ApiResponse res  = null;
        Layer natLayer = null;
        try {
            configuration.getLogger().debug("Run command: 'show-package' " + packageName + "' with details level 'full'");
            res = client.apiCall(loginResponse, "show-package", "{\"name\" : \"" + packageName + "\"}");
        }
        catch (ApiClientException e) {
            logoutReportAndExit("Failed to run show-package command on package: '" + packageName + "'. Aborting. " +
                    ""+ e.getMessage(), MessageType.SEVERE);
        }

        if (res == null || !res.isSuccess()) {
            configuration.getLogger().warning("Failed to run show-package command on package: '" + packageName +
                    "'. Aborting. " + errorResponseToString(res));
        }
        else {
            JSONObject response = res.getPayload();
            if ("true".equalsIgnoreCase(response.get("access").toString())) {
                //Access layers
                StringBuilder loggerInfo = new StringBuilder();
                loggerInfo.append("Access layer(s) that were found in package '").append(packageName).append("' are: ");
                JSONArray jsonArray = (JSONArray) response.get("access-layers");
                configuration.getLogger().debug("Found " + jsonArray.size() + " access layer(s) in package: '" + packageName + "'");
                buildLayers(jsonArray,loggerInfo, accessLayers);
            }

            if ("true".equalsIgnoreCase(response.get("threat-prevention").toString())) {
                //Threat layers
                StringBuilder loggerInfo = new StringBuilder();
                loggerInfo.append("Threat layer(s) that were found in package '").append(packageName).append("' are: ");
                JSONArray jsonArray = (JSONArray) response.get("threat-layers");
                configuration.getLogger().debug("Found " + jsonArray.size() + " threat layer(s) in package: '" + packageName + "'");
                buildLayers(jsonArray, loggerInfo, threatLayers);
            }

            if ("true".equalsIgnoreCase(response.get("nat-policy").toString())) {
                //Nat layer
                natLayer = new Layer();
                natLayer.setName("NAT");
                JSONObject domain = (JSONObject) response.get("domain");
                natLayer.setDomain(domain.get("name").toString());

                if (natLayer.getDomain().equalsIgnoreCase("SMC User")) {
                    natLayer.setDomain("Management server");
                }
                configuration.getLogger().debug("Found nat layer in package: '" + packageName + "'");
                natLayer.setDomainType(domain.get("domain-type").toString());
                natLayer.setHtmlFileName(packageName + " " + natLayer.getName() + "-" + natLayer.getDomain() + ".html");
            }
        }
        return natLayer;
    }

    private static void addNewFlagsToControlDetailsLevel(JSONObject payload) {
        if (configuration.getShowMembership() != null) {
            payload.put("show-membership", configuration.getShowMembership());
        }

        if (configuration.getDereferenceGroupMembers() != null) {
            payload.put("dereference-group-members", configuration.getDereferenceGroupMembers());
        }
    }

    /**
     * This function creates a payload in order to create a html page of a given access layer.
     *
     * @param accessLayer the access {@link Layer} that the html page will be created for
     * @param packageName the package name that the layer belongs to
     *
     * @return True (False in case of an error).
     */
    private static boolean showAccessRulebase(Layer accessLayer, String packageName) {

        //get details of existing access rulebase
        JSONObject payload = new JSONObject();
        configuration.getLogger().info("Starting handling access layer: '" + accessLayer.getName() + "'" );

        payload.put("uid", accessLayer.getUid());
        payload.put("details-level", "full");
        payload.put("use-object-dictionary", true);

        addNewFlagsToControlDetailsLevel(payload);

        if (configuration.showRulesHitCounts()) {
            payload.put("show-hits", true);

            JSONObject hitsSettings = new JSONObject();
            hitsSettings.put("from-date", "1970-1-2");

            payload.put("hits-settings", hitsSettings);
        }

        configuration.getLogger().debug("Run command: 'show-access-rulebase' with payload: " + payload.toJSONString());
        return showRulebase(accessLayer, packageName, "show-access-rulebase", RulebaseType.ACCESS, payload, accessTypes);

    }

    /**
     * This function creates a payload in order to create a html page of a given nat layer.
     *
     * @param natLayer the nat {@link Layer} that the html page will be created for
     * @param packageName the package name that the layer belongs to
     *
     * @return True (False in case of an error).
     */
    private static boolean showNatRulebase(Layer natLayer, String packageName) {

        JSONObject payload = new JSONObject();
        configuration.getLogger().info("Starting handling nat layer: ");

        payload.put("package", packageName);
        payload.put("details-level", "full");
        payload.put("use-object-dictionary", true);

        addNewFlagsToControlDetailsLevel(payload);

        configuration.getLogger().debug("Run command: 'show-nat-rulebase' with payload: " + payload.toJSONString());
        return showRulebase( natLayer, packageName, "show-nat-rulebase", RulebaseType.NAT, payload, natTypes);

    }

    /**
     * Utility function that retrieves the rulebase and writes it to the html page.
     *
     * @param layer the layer whose rulebase is to be written
     * @param packageName the package name that the layer belongs to
     * @param command the show command to be run (access/nat)
     * @param rulebaseType {@link RulebaseType} the rulebase's type
     * @param payloadTemplate the payloadTemplate to run with the command
     * @param types supported rulebases
     *
     * @return True (False in case of an error).
     */
    private static boolean showRulebase(Layer layer, String packageName, String command,
                                        RulebaseType rulebaseType, JSONObject payloadTemplate, String[] types){
        ApiResponse res;

        int totalObjects = 0;
        int limit = configuration.getQueryLimit();

        Set<Layer> inlineLayers = new HashSet<>();


        // Getting the total
        JSONObject gettingTotalPayload = new JSONObject(payloadTemplate);
        gettingTotalPayload.put("details-level", "uid");
        gettingTotalPayload.put("limit", "0");
        try {
            res = client.apiCall(loginResponse, command, gettingTotalPayload);
        }
        catch (ApiClientException e) {
            handleException(e, "Failed to run show rulebase (" + layer.getName() + ")");
            configuration.getLogger().debug("Following the error, creating an empty html file for layer: '"
                    + layer.getName() + "'");
            writeRulebase(layer.getName(), packageName, rulebaseType, layer.getDomain(), inlineLayers, true);
            return false;
        }

        if (res == null || !res.isSuccess()) {
            configuration.getLogger().severe("Failed to run show rulebase ('" + layer.getName()+ "'). "
                    + errorResponseToString(res));
            configuration.getLogger().debug("Following the error, creating an empty html file for layer: '"
                    + layer.getName() + "'");
            writeRulebase(layer.getName(), packageName, rulebaseType, layer.getDomain(), inlineLayers, true);
            return false;
        }

        if(res.getPayload().containsKey("total")){
            totalObjects = Integer.parseInt(res.getPayload().get("total").toString());
        } else {
            configuration.getLogger().info("Rulebase '" + layer.getName() + "' is empty");
        }

        if (totalObjects > 0) {
            final ExecutorService executorService = Executors.newFixedThreadPool(NUMBER_OF_EXECUTORS);
            List<Callable<ApiResponse>> tasks = new ArrayList<>(totalObjects / limit);

            int offset = 0;
            while (offset < totalObjects) {
                JSONObject payload = new JSONObject(payloadTemplate);
                payload.put("offset", offset);
                payload.put("limit", limit);
                tasks.add(new ApiCallTask(command, payload));

                offset += limit;
            }

            try {
                configuration.getLogger().debug("Command [" + command + "] uid " + payloadTemplate.get("uid")
                        + " : Starting execution of " + tasks.size() + " tasks (with " + NUMBER_OF_EXECUTORS + " executor(s))");

                final List<Future<ApiResponse>> futures = executorService.invokeAll(tasks);
                executorService.shutdown();

                boolean serviceTerminatedSuccessfully = executorService.awaitTermination(3, TimeUnit.HOURS);

                if (!serviceTerminatedSuccessfully) {
                    configuration.getLogger().severe("Failed to run show rulebase (" + layer.getName() + "). Timeout after 3 hours.");
                    configuration.getLogger().debug("Following the error, creating an empty html file for layer: '"
                            + layer.getName() + "'");
                    writeRulebase(layer.getName(), packageName, rulebaseType, layer.getDomain(), inlineLayers, true);
                    return false;
                }

                configuration.getLogger().debug("Command [" + command + "] uid " + payloadTemplate.get("uid") + " : Finished execution of " + tasks.size() + " tasks");

                JSONArray rulebases = new JSONArray();

                for (Future<ApiResponse> f : futures) {
                    res = f.get();

                    JSONArray jsonArrayOfObjectDictionary = (JSONArray)res.getPayload().get("objects-dictionary");
                    addObjectsInfoIntoCollections(jsonArrayOfObjectDictionary);
                    final JSONArray currentRulebase = (JSONArray) res.getPayload().get("rulebase");


                    if (!rulebases.isEmpty() && !currentRulebase.isEmpty()) {
                        final JSONObject lastAdded = (JSONObject) rulebases.get(rulebases.size() - 1);
                        final JSONObject firstNew = (JSONObject) currentRulebase.get(0);

                        if (types[0].equalsIgnoreCase(lastAdded.get("type").toString())
                                && types[0].equalsIgnoreCase(firstNew.get("type").toString())
                                && Objects.equals(lastAdded.get("uid").toString(), firstNew.get("uid").toString())) {

                            // firstNew is merged into lastAdded
                            ((JSONArray)lastAdded.get("rulebase")).addAll((JSONArray)firstNew.get("rulebase"));
                            lastAdded.put("to", firstNew.get("to"));

                            // firstNew is deleted
                            currentRulebase.remove(0);
                        }
                    }

                    rulebases.addAll(currentRulebase);

                    if (rulebases.size() > 1) {
                        final JSONArray allExceptTheLastItemRulebase = new JSONArray();
                        allExceptTheLastItemRulebase.addAll(rulebases.subList(0, rulebases.size() - 1));

                        final JSONArray theLastItemRulebase = new JSONArray();
                        theLastItemRulebase.addAll(rulebases.subList(rulebases.size() - 1, rulebases.size()));

                        inlineLayers.addAll(addRulebase(allExceptTheLastItemRulebase, types, rulebaseType));

                        rulebases = theLastItemRulebase;
                    }
                }

                inlineLayers.addAll(addRulebase(rulebases, types, rulebaseType));
            }
            catch (InterruptedException | ExecutionException e) {
                handleException(e, "Failed to run show rulebase (" + layer.getName() + ")");
                configuration.getLogger().debug("Following the error, creating an empty html file for layer: '"
                        + layer.getName() + "'");
                writeRulebase(layer.getName(), packageName, rulebaseType, layer.getDomain(), inlineLayers, true);
                return false;
            }
        }

        configuration.getLogger().debug("Found " + totalObjects + " rules in : '" + layer.getName() + "'");
        configuration.getLogger().debug("Found " + inlineLayers.size() + " inline layer(s)");
        configuration.getLogger().debug("Creating html file for layer: '" + layer.getName() + "'");

        boolean writeRulebaseResult = writeRulebase(layer.getName(), packageName, rulebaseType,
                layer.getDomain(), inlineLayers, false);

        if (!writeRulebaseResult){
            writeRulebase(layer.getName(), packageName, rulebaseType, layer.getDomain(), inlineLayers, true);
        }

        // Write rulebase inline layers
        // In the current design we must create the files of the inline layers after the file of the parent layer is
        // written, otherwise the file of the parent layer will be broken.
        for (Layer inlineLayer : inlineLayers) {
            if(configuration.isKnownInlineLayer(inlineLayer.getUid())){
                configuration.getLogger().debug("Inline layer : '" + inlineLayer.getName() + "'  was already created.");
                continue;
            }
            configuration.setKnownInlineLayers(inlineLayer.getUid());
            configuration.getLogger().debug("Creating inline layer: '" + inlineLayer.getName() + "'");
            if ( !showAccessRulebase(inlineLayer, packageName) ) {
                configuration.getLogger().warning("Failed to create inline-layer, name: '" + inlineLayer.getName() + "'");
            }
        }

        configuration.getLogger().info("Done handling rulebase '" + layer.getName() + "'");

        return writeRulebaseResult;
    }

    /**
     *This function retrieves the rulebase and writes it to the html page.
     *
     * @param packageName the package name that the layer belongs to
     * @param threatLayer the threat layer whose rulebase is to be written
     *
     * @return True (False in case of an error).
     */
    private static boolean showThreatRulebase(String packageName, Layer threatLayer) {

        ApiResponse res;
        boolean finished = false;
        int iterations   = 0;
        int receivedObjects;
        int totalObjects = 0;
        int limit = configuration.getQueryLimit();

        configuration.getLogger().info("Starting handling threat layer: '" + threatLayer.getName() + "'");
        configuration.getLogger().debug("Run command: 'show-threat-rulebase' for rulebase: '" + threatLayer.getUid()
                + "' ('" + threatLayer.getName() + "') with details level 'full'");

        JSONObject payload = new JSONObject();
        payload.put("uid", threatLayer.getUid());
        payload.put("details-level", "full");
        payload.put("use-object-dictionary",true);

        addNewFlagsToControlDetailsLevel(payload);

        while (!finished) {
            payload.put("offset", iterations * limit);
            payload.put("limit", limit);

            try {
                res = client.apiCall(loginResponse, "show-threat-rulebase", payload);
            }
            catch (ApiClientException e) {
                handleException(e, "Failed to run \"show threat-rulebase\" ('" + threatLayer.getName() + "')");
                writeRulebase(threatLayer.getName(),packageName,RulebaseType.THREAT, threatLayer.getDomain(),
                        Collections.<Layer>emptySet(), true);
                return false;
            }

            if (checkAndExitInCaseOfError(res, threatLayer)){
                writeRulebase(threatLayer.getName(),packageName,RulebaseType.THREAT, threatLayer.getDomain(),
                        Collections.<Layer>emptySet(), true);
                return false;
            }

            totalObjects = Integer.parseInt(res.getPayload().get("total").toString());
            if (totalObjects == 0) {
                return true;
            }
            JSONArray jsonArrayOfObjectDictionary = (JSONArray)res.getPayload().get("objects-dictionary");
            addObjectsInfoIntoCollections(jsonArrayOfObjectDictionary);
            JSONArray rulebases = (JSONArray) res.getPayload().get("rulebase");
            threatRulebase(rulebases, threatLayer);

            receivedObjects = Integer.parseInt(res.getPayload().get("to").toString());
            if ( receivedObjects == totalObjects || iterations * limit >= totalObjects ) {
                finished = true;
            }
            iterations++;
        }

        configuration.getLogger().debug("Found " + totalObjects + " rules in: '" + threatLayer.getName() + "'");
        configuration.getLogger().debug("Creating html file for rulebase: '" + threatLayer.getName() + "'");

        configuration.getLogger().info("Done handling rulebase: '" + threatLayer.getName() + "'");

        return(writeRulebase(threatLayer.getName(),packageName,RulebaseType.THREAT, threatLayer.getDomain(),
                Collections.<Layer>emptySet(), false));
    }

    /**
     * This function checks if there are errors or warnings in a given result.
     *
     * @param res the result that will be checked
     * @param threatLayer the threat layer that the error is checked for
     *
     * @return True if there was problem showing the rulebase's layer, otherwise False.
     */
    private static boolean checkAndExitInCaseOfError(ApiResponse res, Layer threatLayer){

        if (res == null){
            configuration.getLogger().severe("Failed to run show-threat-rulebase command ('"+ threatLayer.getName()+"')");
            return true;
        }

        if(!res.isSuccess()) {
            if ("IPS".equalsIgnoreCase(threatLayer.getName())) {
                configuration.getLogger().warning("Failed to run show-threat-rulebase command ('" +
                        threatLayer.getName() + "'): " + errorResponseToString(res) +
                        ". probably IPS does not exist - continue");
            }
            else {
                configuration.getLogger().severe("Failed to run show-threat-rulebase command ('"
                        + threatLayer.getName() + "'). " +errorResponseToString(res));
            }
            return true;
        }

        return false;
    }

    /**
     * This function adds all the rules of a given threat layer into the rules collection,
     * or writes a message into the log file in case of an unsupported rule type (not one of: threat-rule/place-holder)
     * and adds the objects to the object collection.
     *
     * @param rulebases the rulbases whose rules are to be added
     * @param threatLayer The threat layer
     */
    private static void threatRulebase(JSONArray rulebases, Layer threatLayer){

        for (Object ruleObject : rulebases) {

            JSONObject rule = (JSONObject) ruleObject;
            if ("threat-rule".equalsIgnoreCase(rule.get("type").toString())) {
                writeJsonObjectToFile(rule, configuration.getRulbaseWriter(), true);
                String ruleUid = rule.get("uid").toString();

                JSONObject exceptionRulebase = showThreatExceptionRulebase(threatLayer, ruleUid);
                if (exceptionRulebase == null) {
                    continue;
                }
                JSONArray exceptions = (JSONArray) exceptionRulebase.get("rulebase");
                configuration.getLogger().debug("Found "+ exceptions.size() + " exception(s) in rule: '" + ruleUid + "'");

                addRulebase(exceptions, threatTypes, RulebaseType.THREAT);
                JSONArray objects = (JSONArray) exceptionRulebase.get("objects-dictionary");
                addObjectsInfoIntoCollections(objects);
            }
            else if ("place-holder".equalsIgnoreCase(rule.get("type").toString())) {
                writeJsonObjectToFile(rule, configuration.getRulbaseWriter(), true);
            }
            else {
                configuration.getLogger().severe("Unsupported type: " + rule.get("type").toString());
            }
        }
    }

    /**
     *This function returns all the threat exception rules of a given rule and given threat layer .
     *
     * @param threatLayer the threat layer of the threat rule
     * @param ruleUid the rule uid of the rule containing the exception rules
     *
     * @return the exception rules, or null in case of fail.
     */
    private static JSONObject showThreatExceptionRulebase(Layer threatLayer, String ruleUid) {

        ApiResponse res;
        //Creating the payload
        JSONObject payload = new JSONObject();

        payload.put("rule-uid", ruleUid);
        payload.put("details-level", "full");
        payload.put("use-object-dictionary", true);

        addNewFlagsToControlDetailsLevel(payload);

        payload.put("uid", threatLayer.getUid());

        try {
            configuration.getLogger().debug("Run command: 'show-threat-rule-exception-rulebase' " +
                    "for threat layer: '" + threatLayer.getName() + "' ('" + ruleUid
                    + "') with details level 'full'");

            res = client.apiCall(loginResponse,"show-threat-rule-exception-rulebase", payload);
        }
        catch (ApiClientException e) {
            // probably due to a version that does not support threatLayerUid and supports only layerName
            payload.remove("uid");
            payload.put("name", threatLayer.getName());

            try {
                res = client.apiCall(loginResponse,"show-threat-rule-exception-rulebase", payload);
            }
            catch (ApiClientException e1) {
                handleException(e1,"Failed to run show-threat-rule-exception-rulebase command ("
                        + threatLayer.getName() + "'" + threatLayer.getUid() + "')");
                return null;
            }
        }
        if (res == null || !res.isSuccess()) {
            configuration.getLogger().severe("Failed to run show-threat-rule-exception-rulebase command ('"
                    + threatLayer.getName() + "' uid: '" + threatLayer.getUid() + "'). " +
                    errorResponseToString(res));
            return null;
        }
        return res.getPayload();
    }

    /**
     *This function creates an objects html page for a given package.
     *
     * @param packageName package name
     */
    private static void writeDictionary(String packageName){

        try {
            configuration.getObjectsWriter().writeBytes("]");
            configuration.getHtmlUtils().writeObjectsHTML(packageName);
            configuration.getObjectsWriter().seek(0);
            configuration.getObjectsWriter().writeBytes("[");
        }
        catch (IOException e) {
            handleException(e,"Failed to write a HTML file for objects.");
        }
    }

    /**
     *This function creates a gateways html page for a given package.
     *
     * @param packageName package name
     * @param objectsCollection all the objects of the package.
     */
    private static void writeGateways(String packageName, JSONArray objectsCollection){

        try {
            configuration.getHtmlUtils().writeGatewaysHTML(packageName, objectsCollection.toString());
        }
        catch (IOException e) {
            handleException(e, "Failed to create a HTML file for gateways.");
        }
    }

    /**
     *This function is responsible for creating a html page for a given layer.
     *
     * @param layerName the layer's name
     * @param packageName the package's name
     * @param rulebaseType NAT/ACCESS/THREAT
     * @param domain domain
     * @param inlineLayers list of inLineLayers inside the layer
     * @param failedCreatingRulebase True if the tool failed getting the info about that rulebase
     *
     * @return True (False in case of an error).
     */
    private static boolean writeRulebase(String layerName,String packageName, RulebaseType rulebaseType,
                                         String domain, Set<Layer> inlineLayers, boolean failedCreatingRulebase){

        //If it's nat change the layer name
        if(rulebaseType == RulebaseType.NAT){
            layerName = packageName + " " + layerName;
        }

        try {
            configuration.getRulbaseWriter().writeBytes("]");
            configuration.getHtmlUtils().writeRulebaseHTML(layerName, packageName, domain, loginResponse.getApiVersion(),
                    rulebaseType.typeToString(),
                    configuration.getUidToName(),
                    inlineLayers, failedCreatingRulebase);
            configuration.getRulbaseWriter().seek(0);
            configuration.getRulbaseWriter().writeBytes("[");
        }
        catch (IOException e) {
            handleException(e,"Failed to create rulbase page");
            return false;
        }

        return true;
    }

    /**
     * This function creates a new layer object for each layer in the given layers and
     * adds it to the given layers collection.
     *
     * @param layersInfo the layers' information
     * @param loggerInfo the information about the layers that will be written into the log file.
     * @param layers the layers collection
     */
    private static void buildLayers(JSONArray layersInfo, StringBuilder loggerInfo, List<Layer> layers){

        if(layersInfo == null){
            return;
        }
        for (Object layerInfo : layersInfo) {

            JSONObject layerObject = (JSONObject) layerInfo;
            Layer layer = createNewLayer(layerObject);
            layers.add(layer);
            loggerInfo.append(layer.getName());
            loggerInfo.append(", ");
        }
        configuration.getLogger().info(loggerInfo.toString());
    }

    /**
     * This function creates a new {@link Layer} object.
     *
     * @param layerInfo the information for the new layer
     *
     * @return The new layer object
     */
    private static Layer createNewLayer(JSONObject layerInfo){

        Layer layer = new Layer();
        layer.setName(layerInfo.get("name").toString());
        layer.setUid(layerInfo.get("uid").toString());
        layer.setDomain(((JSONObject) layerInfo.get("domain")).get("name").toString());

        if (layer.getDomain().equalsIgnoreCase("SMC User")) {
            layer.setDomain("Management server");
        }
        layer.setDomainType(((JSONObject) layerInfo.get("domain")).get("domain-type").toString());
        layer.setHtmlFileName(layer.getName() + "-" + layer.getDomain() + ".html");

        return layer;
    }

    /**
     * This function adds all of the rules into the rules collection
     * or writes message into the log file in case of an unsupported rule type (from the types list).
     * While handling the rules of the given rulebase, it aggregates all the inline-layers of the rulebase to be
     * handled later.
     *
     * @param rulebase the rulebases that will added to the collection
     * @param types supported rule types
     * @param rulebaseType Type of the rulebase
     *
     * @return Set of the inline-layers
     */
    private static Set<Layer> addRulebase(JSONArray rulebase, String[] types, RulebaseType rulebaseType){

        Set<Layer> inlineLayers = new HashSet<>();

        for (Object ruleObject : rulebase) {
            JSONObject rule = (JSONObject) ruleObject;

            //Handle section
            if (types[0].equalsIgnoreCase(rule.get("type").toString())) {

                // We remove the section rules here to prevent duplication
                // The rules are added later following the section (to get a flat view)
                JSONArray jsonArrayOfRules = (JSONArray) rule.remove("rulebase");
                writeJsonObjectToFile(rule, configuration.getRulbaseWriter(), true);

                if (jsonArrayOfRules != null && jsonArrayOfRules.size() > 0) {
                    for (Object jsonArrayOfRule : jsonArrayOfRules) {
                        JSONObject jsonObject = (JSONObject) jsonArrayOfRule;
                        writeJsonObjectToFile(jsonObject, configuration.getRulbaseWriter(), true);
                        //Check existence of the inline-layer
                        if (rulebaseType == RulebaseType.ACCESS && jsonObject.get("inline-layer") != null) {
                            Layer inlineLayer = createInlineLayer(jsonObject.get("inline-layer").toString());
                            if (inlineLayer != null) {
                                inlineLayers.add(inlineLayer);
                            }
                        }
                    }
                }
            }

            //Handle Rule or place-holder
            else if (types[1].equalsIgnoreCase(rule.get("type").toString()) ||
                    types[2].equalsIgnoreCase(rule.get("type").toString())) {

                writeJsonObjectToFile(rule, configuration.getRulbaseWriter(), true);

                //Check existence of the inline-layer
                if (rulebaseType == RulebaseType.ACCESS && rule.get("inline-layer") != null) {

                    Layer inlineLayer = createInlineLayer(rule.get("inline-layer").toString());
                    if (inlineLayer != null) {
                        inlineLayers.add(inlineLayer);
                    }
                }
            }
            else {
                configuration.getLogger().severe("Unsupported type: " + rule.get("type").toString());
            }
        }

        return inlineLayers;
    }

    /**
     * Creates Inline Layer
     * @param inlineLayerUid Inline layer UID
     *
     * @return Created inline layer
     */
    private static Layer createInlineLayer(String inlineLayerUid)
    {
        ApiResponse res;

        try {
            res = client.apiCall(loginResponse, "show-access-layer", "{\"uid\": \"" + inlineLayerUid + "\"}");
        }
        catch (ApiClientException e) {
            handleException(e, "Failed to run show-access-layer UID: ('" + inlineLayerUid + "')");
            return null;
        }
        if (res == null || !res.isSuccess()) {

            String errorMessage = res != null && res.getErrorMessage() != null ? " Error: '" + res.getErrorMessage() + "'" : "";
            configuration.getLogger().severe("Failed to run show-access-layer UID: ('" + inlineLayerUid + "')" +
                    errorMessage);
            return null;
        }

        return createNewLayer(res.getPayload());
    }

    /**
     * This function adds <uid,name> of the given objects to the collection, and adds the objects to the objects collection.
     *
     * @param objects the objects that will added to the collection
     */
    private static void addObjectsInfoIntoCollections(JSONArray objects)
    {
        if (objects == null) {
            return;
        }

        for (Object o : objects) {
            addObjectInformationIntoCollections((JSONObject) o);
        }
    }

    /**
     * This function adds <uid,name> of a given object to the collection, and adds the object to the objects File.
     *
     * @param object the object that will be added
     */
    private static void addObjectInformationIntoCollections(JSONObject object){

        final Map<String, String> uidToName = configuration.getUidToName();

        String uid = object.get("uid").toString();
        if (!uidToName.containsKey(uid)) {
            //If the object doesn't already exist in the collection
            String name = "";
            if(object.containsKey("name") && object.get("name") != null ){
                name = object.get("name").toString();
            }
            uidToName.put(uid, name);

            addNestedObjectsFromCollections(object);
            addOtherNestedObjects(object);

            writeJsonObjectToFile(object, configuration.getObjectsWriter(), false);
        }
    }

    /**
     * If the input object has fields that contain nested objects, adds them
     * to the objects to dereference queue.
     *
     * @param object the object contains nested objects
     */
    private static void addOtherNestedObjects(JSONObject object)
    {
        for (String field : OBJECT_FIELDS_CONTAINING_NESTED_OBJECTS) {
            Object fieldWithNestedObjects = object.get(field);

            if (fieldWithNestedObjects != null) {
                addNestedObjectToQueue(fieldWithNestedObjects);
            }
        }
    }

    /**
     * If the input object has collections that contain nested objects, adds them
     * to the objects to dereference queue.
     *
     * @param object the object contains nested objects
     */
    private static void addNestedObjectsFromCollections(JSONObject object)
    {
        for (String field : COLLECTION_FIELDS_CONTAINING_NESTED_OBJECTS) {
            Object fieldContainMembers = object.get(field);

            if (fieldContainMembers != null && fieldContainMembers instanceof JSONArray) {
                JSONArray members = (JSONArray) fieldContainMembers;

                for (Object member : members) {
                    addNestedObjectToQueue(member);
                }
            }
        }
    }


    /**
     * This function add specific nested object to the objects to dereference queue.
     *
     * @param nestedObject the object contains nested objects
     */
    private static void addNestedObjectToQueue(Object nestedObject)
    {
        // Input nestedObject could be a JsonObject or a UID string
        if (nestedObject instanceof JSONObject) {
            nestedObject = ((JSONObject) nestedObject).get("uid");
        }

        if ((nestedObject instanceof String) && !(configuration.getUidToName().containsKey(nestedObject))) {
            configuration.getNestedObjectsToRetrieve().offer((String) nestedObject);
        }
    }

    /**
     * This function writes the given json object to a given file
     * @param object the json object need to be written to the file
     * @param fileWriter the file that the json object need to be written to
     * @param rulbase true if the file is rulebases file
     * @return true on success, otherwise false
     */
    private static boolean writeJsonObjectToFile(JSONObject object, RandomAccessFile fileWriter, boolean rulbase){

        if (!rulbase) {
            String type;
            if (object.containsKey(TYPE)) {
                type = (object).get(TYPE).toString();
            }
            else {
                //type field doesn't exist in the object, define the type as "undefined"
                type = UNDEFINED;
            }
            if (allTypes == null) {
                allTypes = new JSONObject();
            }
            if (allTypes.containsKey(type)) {//type already exists, add one to the counter
                int count = Integer.parseInt(allTypes.get(type).toString());
                count++;
                allTypes.put(type, count);
            }
            else {
                allTypes.put(type, 1);
            }
        }

        try {
            if (fileWriter.getFilePointer() > 1) {
                fileWriter.writeBytes(",");
            }
            fileWriter.writeBytes(object.toJSONString());
        }
        catch (IOException e) {
            return false;
        }
        return true;
    }



    /**
     * This function creates a new {@link GatewayAndServer} object according to the given information.
     *
     * @param gatewayAndServerInfo the information for the new gateway
     *
     * @return The new object
     */
    private static GatewayAndServer buildNewGatewayOrServer(JSONObject gatewayAndServerInfo){

        GatewayAndServer gatewayAndServer = new GatewayAndServer();

        String gatewayUid = gatewayAndServerInfo.get("uid").toString();
        gatewayAndServer.setUid(gatewayUid);

        gatewayAndServer.setName(gatewayAndServerInfo.get("name").toString());
        gatewayAndServer.setGatewayObject(gatewayAndServerInfo);

        //Update the policy
        JSONObject policy = (JSONObject) gatewayAndServerInfo.get("policy");
        setGatewayAndServerPolicy(gatewayAndServer, policy);

        return gatewayAndServer;

    }

    /**
     * This function sets the access and threat policy of a given gateway if it exists, and adds the package of the policy
     * to the installed packages list.
     *
     * @param gatewayAndServer the gateway object whose policy is to be set
     * @param policy the policy that is installed on the gateway
     */
    private static void setGatewayAndServerPolicy(GatewayAndServer gatewayAndServer, JSONObject policy) {

        boolean needToAddToRelevantPackages = true;
        String userRequestedGateway = configuration.getUserRequestGateway();

        //In case the user asks to show the policies which are  installed on a specific gateway,
        // only the relevant packages will added
        if (userRequestedGateway != null && !userRequestedGateway.isEmpty() &&
                !userRequestedGateway.equalsIgnoreCase(gatewayAndServer.getName())) {

            configuration.getLogger().info("gateway " + gatewayAndServer.getName() + " is not relevant.");
            needToAddToRelevantPackages = false;
        }

        //If access policy exists
        if (policy.containsKey("access-policy-installed") &&
                "true".equalsIgnoreCase(policy.get("access-policy-installed").toString())) {

            String accessPoliceName = policy.get("access-policy-name").toString();
            gatewayAndServer.setAccessPolicy(accessPoliceName);

            if(needToAddToRelevantPackages && !configuration.getInstalledPackages().contains(accessPoliceName)) {
                configuration.getInstalledPackages().add(accessPoliceName);
            }
        }

        //If threat policy exists
        if (policy.containsKey("threat-policy-installed") &&
                "true".equalsIgnoreCase(policy.get("threat-policy-installed").toString())) {

            String threatPoliceName = policy.get("threat-policy-name").toString();
            gatewayAndServer.setThreatPolicy(threatPoliceName);

            if(needToAddToRelevantPackages && !configuration.getInstalledPackages().contains(threatPoliceName) ) {
                configuration.getInstalledPackages().add(threatPoliceName);
            }
        }
    }

    /**
     * This function creates the index page according to the parameters that appear in the given index object.
     *
     * @param index {@link IndexView}
     */
    private static void buildIndexHtmlPage(IndexView index) {

        try {
            if (!configuration.getHtmlUtils().writeIndexHTML(index.toJson().toString())) {
                configuration.getLogger().severe("Failed to create a HTML file for index");
            }
        }
        catch (FileNotFoundException e) {
            handleException(e, "File not found. failed to create a HTML file for index");
        }
        catch (UnsupportedEncodingException e) {
            handleException(e, "Unsupported encoding. failed to create a HTML file for index");
        }
    }

    /**
     * This function creates the tar file.
     * @param tarPath The temp directory path
     * @param directoryPath The tar file path
     */
    private static void createTarFile(String tarPath, String directoryPath){
        try {
            TarGZUtils.createTarGZ(directoryPath, tarPath, configuration.isDeleteTempFile());
            System.out.println("Result file location: " + tarPath);
        }
        catch (IOException e) {
            handleException(e,"failed to create TarGZ file");
        }
    }

    /**
     * This function writes a given message and the information of a given exception into the log file.
     *
     * @param e the exception
     * @param message need to be written into log file
     */
    private static void handleException(Exception e, String message){

        configuration.getLogger().severe(message + ". Error message: "+ e.getMessage());
    }

    /**
     * This function returns all the local ip's
     *
     * @return a list containing all the local ip's
     */
    private static List<String> getLocalIps(){

        List<String> localIps  = new ArrayList<>();
        Enumeration networkInterfaces;
        try {
            networkInterfaces = NetworkInterface.getNetworkInterfaces();
        }
        catch (SocketException e) {
            return localIps;
        }

        if(networkInterfaces == null){

            return localIps;
        }

        while(networkInterfaces.hasMoreElements())
        {
            NetworkInterface n = (NetworkInterface) networkInterfaces.nextElement();
            Enumeration interAddress = n.getInetAddresses();
            while (interAddress.hasMoreElements())
            {
                InetAddress ip = (InetAddress) interAddress.nextElement();
                localIps.add(ip.getHostAddress());
            }
        }

        return localIps;
    }

    /***
     * This function gets error response and returns string that contain info about the error
     * @param response {@link ApiResponse}
     * @return String represent the error
     */
    private static String errorResponseToString(ApiResponse response){
        String message = "";
        if(response != null){
            message  = "Message: '" + response.getErrorMessage() + "'.";
            if  (response.getErrors()!= null){
                message  += " Errors: " +  response.getErrors().toJSONString();
            }
            if  (response.getErrors() != null){
                message  += " Warnings: '" +  response.getWarnings().toJSONString()+ "'.";
            }
            message  += " Status Code: '" +  response.getStatusCode() + "'";
        }

        return message;
    }

    /**
     * This function exits the program properly:
     * (1) write errors and warning message (if any exist) into the log file
     * (2) calls the 'exit' function from the api client, which logs out from the server and saves the logs to the debug file.
     * (3) creates tar file
     * (4) exits
     *
     * @param message to be printed and written to the log file.
     * @param messageType the type of the message (SEVERE/WARNING/INFO/EXIT WITHOUT MESSAGE)
     * @param createTarFile True if the tar will be created
     */
    private static void logoutReportAndExit(String message, MessageType messageType, boolean createTarFile) {

        int exitCode = MyLogger.SUCCESS_CODE;
        if(loginResponse != null) {
            try {
                client.exit(loginResponse);
            }
            catch (ApiClientException e) {
                configuration.getLogger().severe("Failed to login/logout. Exception: " + e.getMessage());
            }
        }
        if(configuration != null) {
            if (message != null && !message.isEmpty()) {
                //Write severe message to the log file
                switch (messageType) {
                    case SEVERE:
                        configuration.getLogger().severe(message);
                        break;
                    case WARNING:
                        configuration.getLogger().warning(message);
                        break;
                    case INFO:
                        configuration.getLogger().info(message);
                        break;
                }
            }
            exitCode = configuration.getLogger().getMostSevereLevel();
            if (exitCode == MyLogger.SUCCESS_CODE){
                System.out.println("Script finished running successfully!");
                configuration.getLogger().info("Script finished running successfully!");
            }
            else if(exitCode == MyLogger.WARNING_CODE){
                System.out.println("Script finished running with warnings!");
                configuration.getLogger().info("Script finished running with warnings!");
            }
            else{
                System.out.println("Script stopped running due to severe error!");
                configuration.getLogger().info("Script stopped running due to severe error!");
            }


            String tarPath = configuration.getTarGzPath();
            String directoryPath = configuration.getDirectoryPath();


            if(createTarFile) {
                configuration.getLogger().info("dirPath: " + directoryPath);
                configuration.getLogger().info("tarGzPath: " + tarPath);
            }

            freeResources();

            if(createTarFile) {
                createTarFile(tarPath, directoryPath);
            }
        }

        System.exit(exitCode);
    }

    /**
     * This function exits the program properly:
     * (1) write errors and warning message (if any exist) into the log file
     * (2) calls the 'exit' function from the api client, which logs out from the server and saves the logs to the debug file.
     * (3) creates tar file
     * (4) exits
     *
     * @param message to be printed and written to the log file.
     * @param messageType the type of the message (SEVERE/WARNING/INFO/EXIT WITHOUT MESSAGE)
     */
    private static void logoutReportAndExit(String message, MessageType messageType) {
        logoutReportAndExit(message, messageType, true);
    }

    /**
     * This function frees the logger's handlers and deletes the temp file
     */
    private static void freeResources(){

        configuration.closeAndDeleteFile();
        //Free resources
        for (Handler handle : configuration.getLogger().getHandlers()) {
            handle.close();
        }
    }

    private static class ApiCallTask implements Callable<ApiResponse> {

        private JSONObject payload;
        private String command;

        ApiCallTask(String command, JSONObject payload)
        {
            this.payload = payload;
            this.command = command;
        }

        @Override
        public ApiResponse call()
        {
            ApiResponse res;
            try {
                res = client.apiCall(loginResponse, command, payload);
            }
            catch (Exception e) {
                res = null;
            }

            if (res == null || !res.isSuccess()) {
                res = null;
            }

            String log = "Command [" + command + "] uid " + payload.get("uid") + " limit " + payload.get("limit") + " offset " + payload.get("offset") + " ";
            configuration.getLogger().debug(log + (res == null ? "FAILED" : "SUCCESSFUL"));

            return res;
        }
    }
}
