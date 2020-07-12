package com.checkpoint.mgmt_api.examples;

import com.checkpoint.mgmt_api.client.ApiClient;
import com.checkpoint.mgmt_api.objects.GatewayAndServer;
import com.checkpoint.mgmt_api.utils.HtmlUtils;
import org.json.simple.JSONObject;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * This class holds all the configuration parameters.
 * Responsible for defining the parameters according to the arguments passed from the user.
 */
public enum ShowPackageConfiguration {

    INSTANCE;

    private static final String TOOL_VERSION     = "v2.0.5";
    private static final String TAR_SUFFIX       = ".tar.gz";
    private static final String LOG_SUFFIX       = ".elg";
    private static final String PREFIX           = "show_package-";
    //Temp file Names for the data
    private static final String OBJECTS_FILE     = "objects.txt";
    private static final String RULEBASE_FILE    = "rulebase.txt";
    /*Management server IP address*/
    private static String server                 = ApiClient.LOCAL_SERVER_IP;

    /*Set the names of the tar and log files*/
    private static final String tarName;
    private static final String logFileName;
    static {
        SimpleDateFormat formatDate = new SimpleDateFormat("YYYY-MM-dd_HH-mm-ss");
        String date  = formatDate.format(new Date());
        tarName      = PREFIX + date + TAR_SUFFIX;
        logFileName  = PREFIX + date + LOG_SUFFIX;
    }


    /*Login credentials*/
    private static String username;
    private static String password;
    private static String domain;
    private static int port;
    private static boolean userEnteredPort = false;
    private static boolean unsafe          = false;

    /*Define if the temp directory need to be delete*/
    private static boolean deleteTempFile  = true;

    /*Show-package parameters*/
    private static String userRequestGateway;
    private static String userRequestPackage;
    private static boolean showRulesHitCounts    = false;

    private static Integer queryLimit            = null;

    private static final int DEFAULT_QUERY_LIMIT = 10;
    private static Boolean showMembership        = null;

    private static Boolean dereferenceGroupMembers = null;
    private List<String> installedPackages       = new ArrayList<>();
    private static Map<String, String> uidToName = new HashMap<>();
    private static Queue<String> nestedObjectsToRetrieve = new LinkedList<>();
    List<GatewayAndServer> gatewaysWithPolicy    = new ArrayList<>();
    private static Set<String> knownInlineLayers = new HashSet<>();
    private static String publishedSessionUid;

    // Indicates whether to show Access/Threat/NAT policy as part of policy package. Default is true.
    private static boolean doShowAccessPolicy = true;
    private static boolean doShowThreatPolicy = true;
    private static boolean doShowNatPolicy = true;

    /*Logger settings*/

    private static final MyLogger logger = new MyLogger("MyLog", null);
    private FileHandler fileHandler;
    /*Paths settings*/

    private static String tarGzPath          = tarName;
    private static String resultFolderPath;
    //Define if the function needs only to show the existing packages

    private static boolean showPackagesList = false;
    private static String proxy             = "";
    private HtmlUtils htmlUtil              = HtmlUtils.INSTANCE;
    private static RandomAccessFile objectsWriter;

    private static RandomAccessFile rulbaseWriter;
    void initializeParameters(String[] args) throws Exception{

        //Default debug level
        logger.setLevel(MyLevel.DEBUG);

        String debugString = resolveFlags(args);

        //Load html templates
        htmlUtil.readTemplatesFromClassPath();

        //Set directory path
        setTarPath();
        configureLogFile(debugString);
        //Set the writer to the temps file
        setTempFilesWriter();
    }

    /**
     * This function open write access to the temps files
     * @throws IOException In case the write access denied
     */
    void setTempFilesWriter() throws IOException
    {
        //Open write access to the temp file of the objects
      objectsWriter = new RandomAccessFile(new File(resultFolderPath + System.getProperty("file.separator") +
                                                                OBJECTS_FILE), "rw");

      objectsWriter.writeBytes("[");

        //Open write access to the temp file of the rulebase
      rulbaseWriter = new RandomAccessFile(new File(resultFolderPath + System.getProperty("file.separator") +
                                                                RULEBASE_FILE), "rw");

      rulbaseWriter.writeBytes("[");
    }

    /**
     * This function sets the path of the destination folder.
     * If the path was passed as an argument, the function tries to create the folder.
     *
     * @throws Exception in case the function didn't manage to create the folder.
     */
    void setTarPath() throws Exception
    {

        String resultPath = new File("").getAbsolutePath();

        if (resultFolderPath != null && !resultFolderPath.isEmpty()){
            Path resultStringPath = Paths.get(resultFolderPath);

            String resultStringPathToString = resultStringPath.toString();
            if(resultStringPathToString.endsWith(".tar.gz")){
                /* The user entered tar file name */
                tarGzPath = resultStringPathToString;
                resultPath = resultStringPath.getParent().toString();
            }
            else {
                /* The user entered only folder path */
                tarGzPath = resultStringPathToString + System.getProperty("file.separator") + tarName;
                resultPath = resultStringPathToString;
            }
        }

        String folderName = UUID.randomUUID().toString();
        resultFolderPath = resultPath + System.getProperty("file.separator") + folderName;

        File file = new File(resultFolderPath);
        if (!file.exists() && !file.mkdir()) {
            //If the file doesn't exist and couldn't create the file
            System.out.println("Failed to create output directory '" + resultFolderPath + "'");
            throw new Exception("Failed to create output directory '" + resultFolderPath + "'");
        }

        if( !file.isDirectory() ){
            System.out.println("'" + resultFolderPath + "' is not a directory!");
            throw new Exception("'" + resultFolderPath + "' is not a directory!");
        }

        if( file.list().length  > 0 ){
            System.out.println("Directory '" + resultFolderPath + "' is not empty!");
            throw new Exception("Directory '" + resultFolderPath + "' is not empty!");
        }

        File fileTar = new File(tarGzPath);
        if(fileTar.exists()){
            System.out.println("File '" + tarGzPath + "' is already exists!");
            throw new Exception("File '" + tarGzPath + "' is already exists!");
        }

        htmlUtil.setResultFolderPath(resultFolderPath + System.getProperty("file.separator"));

    }

    /**
     * This function parses and handles the given arguments.
     *
     * @param args arguments which are passed from the user (options)
     */
    private String resolveFlags(String[] args) {

        int i = 0;
        StringBuilder debugString = new StringBuilder();
        while(i<args.length) {
            //Go over all the arguments
            String arg = args[i];
            if(arg.length()<2){
                System.out.println("Usage: invalid argument: '"+ arg + "'. The Flag should start with '-' and then the flag letter");
                throw new IllegalArgumentException(
                        "Usage: invalid argument: '"+ arg + "'. The Flag should start with '-' and then the flag letter");
            }
            String flag = String.valueOf(arg);
            Options option = checkFlagExistence(flag);
            if(option!= null){
                if(option.equals(Options.listOfPackages) || option.equals(Options.help)
                        || option.equals(Options.debugInfo) || option.equals(Options.unsafeState)
                        || option.equals(Options.showHitCounts) || option.equals(Options.deleteTempFiles)
                        || option.equals(Options.version)){
                    //Options that don't require a value after the flag
                    option.runCommand("");
                    i++;
                }else {
                    //Options that do require a value after the flag
                    i++;
                    if(i>=args.length){
                        //There is flag without value
                        System.out.println("Usage: The format of an argument should be: <flag , value> ");
                        throw new IllegalArgumentException("Usage: The format of an argument should be: <flag , value> ");
                    }
                    option.runCommand(args[i]);
                    i++;
                }
                debugString.append(" ").append(option.debugString());
            }
            else{
                //Unknown flag
                System.out.println("Unsupported option: "+flag);
                //Show the supported options
                Options.help.runCommand("");
            }
        }
        return debugString.toString();
    }

    /**
     * This function checks if a given flag is one of the known flags.
     *
     * @param flag
     *
     * @return the {@link Options} if the flag is supported, otherwise null.
     */
    private Options checkFlagExistence(String flag){

        for(Options option :Options.values()){
            if(option.getFlag().equals(flag)){
                return option;
            }
        }
        //Flag isn't supported
        return null;
    }

    /**
     * This function configures the logger with handler and formatter
     */
    private void configureLogFile(String debugString)
    {
        //Set log file's name
        String logFile = resultFolderPath + System.getProperty("file.separator") + logFileName;
        logger.info("Log file location: " + logFile);
        try {
            fileHandler = new FileHandler(logFile);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        //Handler settings
        logger.addHandler(fileHandler);
        logger.setUseParentHandlers(false);
        fileHandler.setFormatter(new MyFormatter());

        logger.debug("The parameters that were received: " + debugString);
    }

    /**
     *This function creates login payload.
     * @param loginAsRoot True, if the login is to local host.
     * @return {@link JSONObject} containing the username, password and domain
     */
    JSONObject createPayloadForLogin(boolean loginAsRoot){

        JSONObject payload = new JSONObject();
        String missing_arg;
        if (!loginAsRoot) {
            if (username != null && !username.isEmpty()) {
                payload.put("user", username);
            }
            else{
                String userName = readUserName();
                payload.put("user", userName);
            }
            if (password != null && !password.isEmpty()) {
                payload.put("password", password);
            }
            else{
                char[] passwordFromConsole = readPassword();
                payload.put("password", new String(passwordFromConsole));
            }
        }
        if(domain != null && !domain.isEmpty()){
            payload.put("domain",domain);
        }

        // Read only flag
        payload.put("read-only", true);
        logger.debug("Login with 'read-only' flag. ");

        return payload;
    }

    /**
     * This function closes and deletes the temp files
     * @return true on success, otherwise false.
     */
    boolean closeAndDeleteFile(){
        try {
            if (objectsWriter != null) {
                objectsWriter.close();
                Files.delete(Paths.get(resultFolderPath +  System.getProperty("file.separator") + OBJECTS_FILE));
            }
            if (rulbaseWriter != null) {
                rulbaseWriter.close();
                Files.delete(Paths.get(resultFolderPath +  System.getProperty("file.separator") + RULEBASE_FILE));
            }
        }
        catch (IOException e) {
            return false;
        }
        return true;
    }

    /**
     * This function reads the password from the console with echoing disabled
     * @return user's password
     */
    public char[] readPassword(){
        Console console = System.console();
        if (console == null) {
            logger.severe("Couldn't get Console instance");
            System.out.println("Couldn't get Console instance");
            System.exit(1);
        }

        return console.readPassword("Enter password: ");
    }

    /**
     * This function reads the user name from the console
     * @return user's name
     */
    public String readUserName(){
        Console console = System.console();
        if (console == null) {
            logger.severe("Couldn't get Console instance");
            System.out.println("Couldn't get Console instance");
            System.exit(1);
        }

        return console.readLine("Enter user name: ");
    }

    /**
     * Get the IP of the management server.
     *
     * @return the IP
     */
    String getServer()
    {
        return server;
    }

    /**
     * Get the domain name
     *
     * @return The domain name
     */
    String getDomain()
    {
        if(domain == null){
            return "";
        }
        return domain;
    }

    String getToolVersion()
    {
        return TOOL_VERSION;
    }

    /**
     * Get the package name that the user asked to show.
     *
     * @return package name
     */
    String getUserRequestPackage()
    {
        return userRequestPackage;
    }

    /**
     * Get the gateway name that a user asked to show
     *
     * @return gateway name
     */
    String getUserRequestGateway()
    {
        return userRequestGateway;
    }

    Map<String, String> getUidToName()
    {
        return uidToName;
    }

    Queue<String> getNestedObjectsToRetrieve()
    {
        return nestedObjectsToRetrieve;
    }

    String getTarGzPath()
    {
        return tarGzPath;
    }

    MyLogger getLogger()
    {
        return logger;
    }

    String getUsername()
    {
        return username;
    }

    String getPassword()
    {
        return password;
    }

    RandomAccessFile getObjectsWriter()
    {
        return objectsWriter;
    }

    RandomAccessFile getRulbaseWriter()
    {
        return rulbaseWriter;
    }

    List<String> getInstalledPackages()
    {
        return installedPackages;
    }

    boolean isDeleteTempFile(){
        return deleteTempFile;
    }

    boolean isUnsafe()
    {
        return unsafe;
    }

    boolean showPackagesList(){
        return showPackagesList;
    }

    String getProxy(){
        return proxy;
    }

    int getPort(){
        return port;
    }

    boolean isUserEnteredPort(){
        return userEnteredPort;
    }

    String getDirectoryPath()
    {
        return resultFolderPath;
    }

    HtmlUtils getHtmlUtils(){
        return htmlUtil;
    }

    List<GatewayAndServer> getGatewaysWithPolicy(){
        return gatewaysWithPolicy;
    }

    void setGatewaysWithPolicy(GatewayAndServer gateway){
        gatewaysWithPolicy.add(gateway);
    }

    public void setKnownInlineLayers(String knownInlineLayer)
    {
        knownInlineLayers.add(knownInlineLayer);
    }

    public boolean isKnownInlineLayer(String knownInlineLayer){
        return knownInlineLayers.contains(knownInlineLayer);

    }

    public String getPublishedSessionUid() {
        return publishedSessionUid;
    }

    public String getResultFolderPath()
    {
        return resultFolderPath;
    }

    public Integer getQueryLimit()
    {
        return queryLimit == null ? DEFAULT_QUERY_LIMIT : queryLimit;
    }

    public boolean showRulesHitCounts() { return showRulesHitCounts; }

    public Boolean getShowMembership() { return showMembership; }

    public Boolean getDereferenceGroupMembers()
    {
        return dereferenceGroupMembers;
    }

    public boolean showAccessPolicyFlag() { return doShowAccessPolicy; }

    public boolean showThreatPolicyFlag() { return doShowThreatPolicy; }

    public boolean showNatPolicyFlag() { return doShowNatPolicy; }

    /**
     * This enum defines the known flags and the actions each of them does.
     */
    private enum Options
    {
        serverName("-m") {
            void runCommand(String value)
            {
                server = value;
            }

            String value(){
                return " server-IP";
            }

            void flagToString()
            {
                System.out.println("\tManagement server ip address.\n\tDefault value is {" + ApiClient.LOCAL_SERVER_IP + "}.");
            }

            String debugString()
            {
                return "server:(-m)=" + server;
            }
        },
        portNumber("-n") {
            void runCommand(String value)
            {
                port = Integer.parseInt(value);
                userEnteredPort = true;
            }

            String value(){
                return " port-number";
            }


            void flagToString()
            {
                System.out.println("\tPort of WebAPI server on management server.\n\tDefault {" + ApiClient.DEFAULT_PORT+ "}.");
            }

            String debugString()
            {
                return "port:(-n)=" + port;
            }
        },
        gatewayAndServer("-g") {
            void runCommand(String value)
            {
                userRequestGateway = value;
            }

            void flagToString()
            {
                System.out.println("\tGateway name.\n\tShows the policy packages which are installed on this gateway.");
            }

            String value(){
                return " gateway-name";
            }

            String debugString()
            {
                return "userRequestGateway:(-g)=" + userRequestGateway;
            }
        },
        userName("-u") {
            void runCommand(String value)
            {
                username = value;
            }

            String value(){
                return " user-name";
            }

            void flagToString()
            {
                System.out.println("\tManagement administrator user name.");
            }

            String debugString()
            {
                return "username:(-u)=" + username;
            }
        },
        adminPassword("-p") {
            void runCommand(String value)
            {
                password = value;
            }

            void flagToString()
            {
                System.out.println("\tManagement administrator password.");
            }

            String value(){
                return " password";
            }

            String debugString()
            {
                return "password:(-p)=*****";
            }
        },
        domainName("-d") {
            void runCommand(String value)
            {
                domain = value;
            }

            void flagToString()
            {
                System.out.println("\tName, uid or IP-address of the management domain.");
            }
            String debugString()
            {
                return "domain:(-d)=" + domain;
            }

            String value(){
                return " domain-name";
            }
        },
        unsafeState("-b") {
            void runCommand(String value)
            {
                unsafe = true;
            }

            void flagToString()
            {
                System.out.println("\tUNSAFE! Ignore certificate verification.\n\tDefault {false}");
            }
            String debugString()
            {
                return "unsafe:(-b)=" + unsafe;
            }

            String value(){
                return "";
            }
        },
        deleteTempFiles("-r") {
            void runCommand(String value)
            {
                deleteTempFile = false;
            }

            void flagToString()
            {
                System.out.println("\tKeep show package temporary folder.");
            }
            String debugString()
            {
                return "deleteTemporaryFile:(-r)=" + deleteTempFile;
            }
            String value(){
                return "";
            }
        },
        productDirectory("-o") {
            void runCommand(String value)
            {
                resultFolderPath = value;
            }

            void flagToString()
            {
                System.out.println("\tResult path.\n\tPath where to store the result tar file." +
                                           "\n\tOr path with "+ TAR_SUFFIX + " suffix in order to set tar file name." +
                                           "\n\tThe default is the current directory.");
            }
            String debugString()
            {
                return "folderPath:(-o)=" + resultFolderPath;
            }

            String value(){
                return " path";
            }
        },
        packageName("-k") {
            void runCommand(String value)
            {
                userRequestPackage = value;
            }

            void flagToString()
            {
                System.out.println("\tPackage name.\n\tThe policy package to show.");
            }
            String debugString()
            {
                return "userRequestPackage:(-k)=" + userRequestPackage;
            }
            String value(){
                return " package-name";
            }
        },

        listOfPackages("-v") {
            void runCommand(String value)
            {
                showPackagesList = true;
            }

            void flagToString()
            {

                System.out.println("\tList the existing policy packages.");
            }
            String debugString()
            {
                return "showPackagesList:(-v)=" + showPackagesList;
            }

            String value(){
                return "";
            }

        },
        showHitCounts("-c") {
            void runCommand(String value)
            {
                showRulesHitCounts = true;
            }

            String value(){
                return "";
            }

            void flagToString()
            {
                System.out.println("\tShow Access Policy rules hit counts.\n\tDefault {false}");
            }

            String debugString()
            {
                return "showRulesHitCounts:(-c)=" + showRulesHitCounts;
            }
        },
        queryLimit("--query-limit") {
            void runCommand(String limitString)
            {
                final Integer limit;

                try {
                    limit = Integer.valueOf(limitString);
                    if (limit < 1 || limit > 500) {
                        throw new IllegalArgumentException();
                    }
                }
                catch (IllegalArgumentException e) {
                    final String errorMessage = "The value of --query-limit must be an integer in range from 1 to 500";
                    System.out.println(errorMessage);
                    throw new IllegalArgumentException(errorMessage);
                }

                ShowPackageConfiguration.queryLimit = limit;
            }

            void flagToString()
            {
                System.out.println("\tNo more than that many results will be returned on each call." +
                        "\n\tIncrease the limit to get a faster execution (because of less number of calls in total)" +
                        "\n\tDecrease the limit when your calls are hitting the timeout (e.g. when your rulebase is huge and complex)" +
                        "\n\tThe limit must be in range from 1 to 500" +
                        "\n\tDefault {" + DEFAULT_QUERY_LIMIT + "}");
            }
            String debugString()
            {
                return "queryLimit:(--query-limit)=" + ShowPackageConfiguration.queryLimit;
            }
            String value(){
                return " limit";
            }
        },
        showMembershipOption("--show-membership") {
            void runCommand(String value)
            {
                if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                    final String errorMessage = "The value of --show-membership is invalid (must be true or false)";
                    System.out.println(errorMessage);
                    throw new IllegalArgumentException(errorMessage);
                }

                ShowPackageConfiguration.showMembership = Boolean.parseBoolean(value);
            }

            String value(){
                return " (true|false)";
            }

            void flagToString()
            {
                System.out.println("\tWhether to calculate groups membership for the objects (\"groups\" field)" +
                        "\n\tThis flag is supported from R80.10 Jumbo HF take 70");
            }

            String debugString()
            {
                return "showMembership:(--show-membership)=" + ShowPackageConfiguration.showMembership;
            }
        },
        dereferenceGroupMembers("--dereference-group-members") {
            void runCommand(String value)
            {
                if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                    final String errorMessage = "The value of --dereference-group-members is invalid (must be true or false)";
                    System.out.println(errorMessage);
                    throw new IllegalArgumentException(errorMessage);
                }

                ShowPackageConfiguration.dereferenceGroupMembers = Boolean.parseBoolean(value);
            }

            String value(){
                return " (true|false)";
            }

            void flagToString()
            {
                System.out.println("\tWhether to dereference group members." +
                        "\n\tThis flag is supported from R80.10 Jumbo HF take 70");
            }

            String debugString()
            {
                return "dereferenceGroupMembers:(--dereference-group-members)=" + ShowPackageConfiguration.dereferenceGroupMembers;
            }
        },
        proxySetting("-x") {
            void runCommand(String value)
            {
                proxy = value;
            }

            void flagToString()
            {
                System.out.println("\tProxy settings example: user:password@proxy.server:port");
            }
            String debugString()
            {
                return "proxy:(-x)=" + proxy;
            }
            String value(){
                return " proxy-settings";
            }
        },
        debugInfo("-s") {
            void runCommand(String value)
            {
                logger.setLevel(MyLevel.INFO);
            }

            void flagToString()
            {
                System.out.println("\tMinimal debug information.");
            }
            String debugString()
            {
                return "debug:(-s)=" + true;
            }
            String value(){
                return "";
            }
        },
        version("--version") {
            void runCommand(String value)
            {
                System.out.println(TOOL_VERSION);
                System.exit(0);
            }

            void flagToString()
            {
                System.out.println("\tPrint version and exit.");
            }
            String debugString()
            {
                return "version:(--version)=" + true;
            }
            String value(){
                return "";
            }
        },
        help("-h") {
            /**
             * This function prints the explanation on all the flags
             * @param value
             */
            void runCommand(String value)
            {
                System.out.println("\nshow-package version: " + TOOL_VERSION + "\n");
                System.out.println("\nweb_api_show_package.sh optional-switches\n");
                System.out.println("optional-switches:");
                System.out.println("---------------");
                for (Options option : Options.values()) {
                    System.out.println("[" + option.getFlag() + option.value() + "]");
                    option.flagToString();
                }
                System.out.println();
                System.exit(0);
            }

            void flagToString()
            {

                System.out.println("\tUsage guide.");
            }
            String debugString()
            {
                return "help:(-h)=" + true;
            }

            String value(){
                return "";
            }
        },
        switchSession("--published-session-uid"){
            @Override
            void flagToString()
            {
                System.out.println("\tShow package as of the input published session. If not specified, will show the last published package");
            }

            @Override
            void runCommand(String value)
            {
                publishedSessionUid = value;
            }

            @Override
            String debugString()
            {
                return "published session uid: (--published-session-uid)=" + publishedSessionUid;
            }

            @Override
            String value()
            {
                return " published session uid";
            }
        },
        showAccessPolicy("--show-access-policy"){
            @Override
            void flagToString()
            {
                System.out.println("\tIndicates whether to show access policy as part of policy package. Default value is True.");
            }

            @Override
            void runCommand(String value)
            {
                if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                    final String errorMessage = "The value of --show-access-policy is invalid (must be true or false)";
                    System.out.println(errorMessage);
                    throw new IllegalArgumentException(errorMessage);
                }
                ShowPackageConfiguration.doShowAccessPolicy = Boolean.parseBoolean(value);
            }

            @Override
            String debugString()
            {
                return "Show access policy (--show-access-policy)=" + doShowAccessPolicy;
            }

            @Override
            String value()
            {
                return "  (true|false)";
            }
        },
        showThreatPolicy("--show-threat-policy"){
            @Override
            void flagToString()
            {
                System.out.println("\tIndicates whether to show threat policy as part of policy package. Default value is True.");
            }

            @Override
            void runCommand(String value)
            {
                if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                    final String errorMessage = "The value of --show-threat-policy is invalid (must be true or false)";
                    System.out.println(errorMessage);
                    throw new IllegalArgumentException(errorMessage);
                }

                ShowPackageConfiguration.doShowThreatPolicy = Boolean.parseBoolean(value);
            }

            @Override
            String debugString()
            {
                return "Show threat policy (--show-threat-policy)=" + doShowThreatPolicy;
            }

            @Override
            String value()
            {
                return "  (true|false)";
            }
        },
        showNatPolicy("--show-nat-policy"){
            @Override
            void flagToString()
            {
                System.out.println("\tIndicates whether to show NAT policy as part of policy package. Default value is True.");
            }

            @Override
            void runCommand(String value)
            {
                if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                    final String errorMessage = "The value of --show-nat-policy is invalid (must be true or false)";
                    System.out.println(errorMessage);
                    throw new IllegalArgumentException(errorMessage);
                }
                ShowPackageConfiguration.doShowNatPolicy = Boolean.parseBoolean(value);
            }

            @Override
            String debugString()
            {
                return "Show nat policy (--show-nat-policy)=" + doShowNatPolicy;
            }

            @Override
            String value()
            {
                return "  (true|false)";
            }
        },
        ;


        private String flag;

        Options(String flag)
        {
            this.flag = flag;
        }

        String getFlag()
        {
            return flag;
        }

        //This function returns an explanation on the flag
        abstract void flagToString();

        abstract void runCommand(String value);

        abstract String debugString();

        abstract String value();
    }

}

/**********************************************/

class MyFormatter extends Formatter
{
    @Override
    public String format(LogRecord record) {
        return MessageFormat.format("[{0} {1}.{2}(){3}]: {4}\n", new Date(record.getMillis()),
                                            record.getSourceClassName(),
                                            record.getSourceMethodName(),
                                            record.getLevel(),
                                            record.getMessage());
    }
}

