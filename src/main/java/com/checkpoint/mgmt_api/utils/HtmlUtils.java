package com.checkpoint.mgmt_api.utils;

import com.checkpoint.mgmt_api.objects.Layer;
import org.json.simple.JSONValue;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * This is a utility class that builds html pages based on the given parameters
 */
public enum HtmlUtils {

    INSTANCE;

    enum FileType
    {
        RULEBASE, OBJECTS
    }

    class RulebaseData {

        private String rulebaseDataContent;

        // Flag indicate if the rulebse failed
        private boolean failedCreatingRulebase;

        // Map from the layer UID to the layer file name
        private Map<String, String> inlineLayerUidToFileNameMap = new HashMap<>();

        public RulebaseData(String rulebaseDataContent, boolean failedCreatingRulbase ) {
            this.rulebaseDataContent = rulebaseDataContent;
            this.failedCreatingRulebase = failedCreatingRulbase;

        }

        public RulebaseData(String rulebaseDataContent, Set<Layer> inlineLayers, boolean failedCreatingRulbase) {
            this(rulebaseDataContent, failedCreatingRulbase);

            for (Layer inlineLayer : inlineLayers) {
                inlineLayerUidToFileNameMap.put(inlineLayer.getUid(), inlineLayer.getHtmlFileName());
            }
        }

        public String getRulebaseDataContent()
        {
            return rulebaseDataContent;
        }

        public Map<String, String> getInlineLayerUidToFileNameMap()
        {
            return inlineLayerUidToFileNameMap;
        }

        public boolean isFailedCreatingRulebase(){
            return failedCreatingRulebase;
        }
    }

    /**
     * This class contains details needed to write the html file
     */
    private static class FileDetails {
        //In case the html file is rulebase needed info on the rulebase
        private RulebaseData rulebaseData;
        //In case the html file is rulebase needed the map to connect between name to uid
        private Map<String,String> uidToName;
        //The temp file contains the json objects
        private String objectsFileName;

        private List<String> templateLines;
        private String htmlFileName;
        private String jsonFileName;


        FileDetails(String objectsFileName, List<String> templateLines, String htmlFileName, String jsonFileName){
            this(objectsFileName, templateLines, htmlFileName, jsonFileName, null, null);
        }

        FileDetails(String objectsFileName, List<String> templateLines, String htmlFileName,String jsonFileName,
                    Map<String,String> uidToName, RulebaseData rulebaseData){
            this.objectsFileName = objectsFileName;
            this.templateLines = templateLines;
            this.uidToName = uidToName;
            this.rulebaseData = rulebaseData;
            this.htmlFileName = htmlFileName;
            this.jsonFileName = jsonFileName;


        }

        List<String> getTemplateLines()
        {
            return templateLines;
        }

        public String getHtmlFileName()
        {
            return htmlFileName;
        }

        public String getObjectsFileName()
        {
            return objectsFileName;
        }

        public Map<String, String> getUidToName()
        {
            return uidToName;
        }

        public RulebaseData getRulebaseData()
        {
            return rulebaseData;
        }

        public String getJsonFileName()
        {
            return jsonFileName ;
        }

    }

    //========================================//

    //Template namespace
    public static final String TEMPLATES_NAMESPACE = "com/checkpoint/mgmt_api/templates";

    //Template file names
    public static final String RULEBASE_HTML_TEMPLATE = "rulebase.tpl.html";
    public static final String OBJECTS_HTML_TEMPLATE  = "objects.tpl.html";
    public static final String INDEX_HTML_TEMPLATE    = "index.tpl.html";

    public static final String[] ALL_TEMPLATES = new String[]{INDEX_HTML_TEMPLATE, OBJECTS_HTML_TEMPLATE, RULEBASE_HTML_TEMPLATE};

    //Temp file that holds the objects info
    private static final String OBJECTS_FILE  = "objects.txt";
    //Temp file that holds the rulbase info
    private static final String RULEBASE_FILE = "rulebase.txt";

    //Format of place holder in template files
    private static final String TEMPLATE_PLACE_HOLDER  = "/*<%%>*/";

    //Suffix
    private static final String HTML_SUFFIX   = ".html";
    private static final String JSON_SUFFIX   = ".json";

    //Set encoding format
    private static final Charset ENCODING    = StandardCharsets.UTF_8;
    //Buffer reader size
    private static final int BUFFER_SIZE = 1024;

    private String resultFolderPath;
    private Map<String, List<String>> templatesMap = new HashMap<>();

    /**
     * This function creates a rulebase html page by replacing the dynamic content in the template with the relevant information
     *
     * @param layerName layer's name
     * @param packageName package's name
     * @param domain domain name
     * @param rulebaseType rulebase type (THREAT/IPS/ACCESS/NAT)
     * @param failedCreatingRulbase True if the html file will show an error.
     *
     * @throws IOException
     */

    public void writeRulebaseHTML(String layerName, String packageName, String domain, String apiVersion,
                                  String rulebaseType ,Map<String,String> uidToName,
                                  Set<Layer> inlineLayers, boolean failedCreatingRulbase, boolean showRuleUid) throws IOException {

        //In case of nat set the domain name to be 'Management server'
        if(domain == null || domain.isEmpty()) {
            domain = "Management server";
        }

        String rulebase = "{\"api-version\" : \"" + apiVersion + "\", \"showRuleUid\" : \"" + showRuleUid + "\", " +
                "\"domain\" : \"" + domain + "\", \"package\" : \""
                + packageName + "\", " + "\"layer\" : \"" + layerName + "\", \"type\" : \"" + rulebaseType + "\"}";


        String htmlFileName = resultFolderPath +layerName + "-" + domain + HTML_SUFFIX;
        String jsonFileName = resultFolderPath +layerName + "-" + domain + JSON_SUFFIX;
        String objectsFile =  resultFolderPath + RULEBASE_FILE;
        FileDetails details = new FileDetails(objectsFile,getRulebaseHtmlTemplateLines(),htmlFileName, jsonFileName,
                                              uidToName, new RulebaseData(rulebase, inlineLayers, failedCreatingRulbase));
        createHtmlFile(details, FileType.RULEBASE);

    }

    /**
     * This function creates the html file according to the given type file
     * @param details the details for the html file
     * @param fileType {@link FileDetails} contain info about the html file
     * @throws IOException
     */
    public void createHtmlFile(FileDetails details, FileType fileType) throws IOException
    {
        try (PrintStream writer = new PrintStream(new File(details.getHtmlFileName()))) {

            for (String line : details.getTemplateLines()) {
                if (!line.contains(TEMPLATE_PLACE_HOLDER))
                    writer.println(line);
                else {
                    if (fileType == FileType.OBJECTS) {
                        setDataInHtmlFile(writer, details);
                    }
                    else if (fileType == FileType.RULEBASE) {
                        setRulebaseHtmlFile(writer, details);
                    }
                }
            }
        }
    }

    /**
     * This function writes the info of the rulbase to the html file
     * @param htmlFile The html to write to
     * @param details {@link FileDetails} contain info about the html file
     * @throws IOException
     */
    public void setRulebaseHtmlFile(PrintStream htmlFile , FileDetails details) throws IOException{

        htmlFile.println("\t\tvar rulebase = " + details.getRulebaseData().getRulebaseDataContent() + ";");
        htmlFile.print("\t\tvar uid_to_name = ");
        htmlFile.print(JSONValue.toJSONString(details.getUidToName()));
        htmlFile.println(";");

        htmlFile.print("\t\tvar failed_creating_layer = ");
        htmlFile.print(JSONValue.toJSONString(details.getRulebaseData().isFailedCreatingRulebase()));
        htmlFile.println(";");

        htmlFile.print("\t\tvar inline_layer_uid_to_file_name = ");
        htmlFile.print(JSONValue.toJSONString(details.getRulebaseData().getInlineLayerUidToFileNameMap()));
        htmlFile.println(";");

        setDataInHtmlFile(htmlFile, details);
    }

    /**
     * This function writes the data to the html file
     * @param htmlFile The html to write to
     * @param details {@link FileDetails} contain info about the html file
     * @throws IOException
     */
    private void setDataInHtmlFile(PrintStream htmlFile, FileDetails details) throws IOException
    {
        htmlFile.print("\t\tvar data = ");
        try(FileInputStream reader = new FileInputStream(details.getObjectsFileName());
            PrintStream jsonWriter = new PrintStream(new File(details.getJsonFileName()))) {

            //If the temp file is empty return
            if (reader.available() == 0){
                return;
            }

            //Read from temp file until get to EOF and write the info to the html file and json file.
            int resRead;
            byte[] buffer = new byte[BUFFER_SIZE];
            while((resRead = reader.read(buffer)) != -1)
            {
                if (resRead < BUFFER_SIZE){
                    htmlFile.write(Arrays.copyOfRange(buffer,0,resRead));
                    jsonWriter.write(Arrays.copyOfRange(buffer,0,resRead));
                }
                else {
                    htmlFile.write(buffer);
                    jsonWriter.write(buffer);
                }
                htmlFile.flush();
                jsonWriter.flush();
            }
        }
        finally {
            //Close the list
            htmlFile.println(";");
            //Delete the info from the temp file
            try(PrintWriter writer = new PrintWriter(details.getObjectsFileName())) {
                writer.print("");
            }
        }
    }
    /**
     *This function creates the objects html page by replacing the dynamic content in the template files with the relevant
     *  information
     *
     * @param packageName the package's name that the objects belong to
     *
     * @throws FileNotFoundException
     * @throws UnsupportedEncodingException
     */
   public void writeObjectsHTML(String packageName) throws IOException
   {
       String objectsFile = resultFolderPath + OBJECTS_FILE;
       String htmlFileName = resultFolderPath + packageName + "_objects" + HTML_SUFFIX;
       String jsonFileName = resultFolderPath + packageName + "_objects" + JSON_SUFFIX;
       FileDetails details = new FileDetails(objectsFile, getObjectsHtmlTemplateLines(), htmlFileName, jsonFileName);
       createHtmlFile(details, FileType.OBJECTS);
    }

    /**
     *This function creates the gateways html page by replacing the dynamic content in the template files with the relevant
     *  information
     *
     * @param packageName the package's which installed on the gateways
     *
     * @throws FileNotFoundException
     * @throws UnsupportedEncodingException
     */
    public boolean writeGatewaysHTML(String packageName, String objectsAsJsonString ) throws IOException
    {
        String pageName = packageName +"_gateway_objects";
        return writeToHtmlPage(pageName, objectsAsJsonString, getObjectsHtmlTemplateLines());
    }

    /**
     * This function creates the index html page by replacing the dynamic content in the template with the relevant information
     *
     * @param index the information about the index
     * @return true on success.
     *
     * @throws FileNotFoundException
     * @throws UnsupportedEncodingException
     */
    public boolean writeIndexHTML(String index) throws FileNotFoundException, UnsupportedEncodingException {

        return writeToHtmlPage("index", index, getIndexHtmlTemplateLines());
    }

    /**
     * Util function in order to write html page
     *
     * @param pageName the html page name
     * @param stringToReplace the information that needs to be written to the page
     * @param objectsHtmlTemplateLines the lines of the template file which the information will be written to
     *
     * @return true on success.
     * @throws FileNotFoundException
     * @throws UnsupportedEncodingException
     */
    private boolean writeToHtmlPage(String pageName, String stringToReplace, List<String> objectsHtmlTemplateLines)
            throws FileNotFoundException, UnsupportedEncodingException{

        if(objectsHtmlTemplateLines == null || objectsHtmlTemplateLines.isEmpty()) {
            return false;
        }

        try(
                PrintWriter htmlWriter = new PrintWriter(resultFolderPath +pageName +HTML_SUFFIX, ENCODING.displayName());
                PrintWriter jsonWriter = new PrintWriter(resultFolderPath + pageName + JSON_SUFFIX)
        )
        {
            replaceTemplate(stringToReplace, objectsHtmlTemplateLines, htmlWriter, jsonWriter);
        }

        return true;
    }

    /**
     *This function replaces the place holder in the html page with the wanted information,
     *  and writes the wanted information in to json page
     *
     * @param replaceString the information needed to insert instead of the place holder
     * @param objectsHTMLTemplate the html page with the place holder
     * @param htmlWriter the html writer
     * @param jsonWriter the json writer
     */
    private void replaceTemplate(String replaceString, List<String> objectsHTMLTemplate,
                                 PrintWriter htmlWriter, PrintWriter jsonWriter ){

        for(String templateLine : objectsHTMLTemplate) {
            if(templateLine.contains(TEMPLATE_PLACE_HOLDER)) {
                String stringToReplace = "var data = " + replaceString + ";\n";
                htmlWriter.println(templateLine.replace(TEMPLATE_PLACE_HOLDER, stringToReplace));
                jsonWriter.println(replaceString);
            }
            else{
                htmlWriter.println(templateLine);
            }
        }
    }

    private List<String> readHTMLTemplateLines(InputStream in) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
            List<String> result = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                result.add(line);
            }

            return result;
        }
    }

    /**
     * Set the folder path
     *
     * @param resultFolderPath
     */
    public void setResultFolderPath(String resultFolderPath) {
        this.resultFolderPath = resultFolderPath;
    }

    public void readTemplatesFromClassPath() throws Exception {
        final ClassLoader cl = getClass().getClassLoader();

        for (String template : ALL_TEMPLATES) {
            try (InputStream in = cl.getResourceAsStream(TEMPLATES_NAMESPACE + "/" + template)) {
                if (in == null) {
                    String errorMessage = "Template [" + template + "] was not found in classpath.";
                    System.out.println(errorMessage);
                    throw new Exception(errorMessage);
                }

                templatesMap.put(template, readHTMLTemplateLines(in));
            }
        }
    }

    /**
     * Get the path contains html template of the rulebase
     *
     * @return the path
     */
    private List<String> getRulebaseHtmlTemplateLines()
    {
        return getTemplatePath(RULEBASE_HTML_TEMPLATE);
    }

    /**
     * Get the path contains html template of index
     *
     * @return the path
     */
    private List<String> getIndexHtmlTemplateLines()
    {
        return getTemplatePath(INDEX_HTML_TEMPLATE);
    }

    /**
     * Get the path contains html template of objects
     *
     * @return the path
     */
    private List<String> getObjectsHtmlTemplateLines()
    {
        return getTemplatePath(OBJECTS_HTML_TEMPLATE);
    }

    /**
     * This function builds the path of a given template, according to the existence of  the template's name.
     *
     * @param templateName the name of the template
     *
     * @return the path
     */
    private List<String> getTemplatePath(String templateName){
        return templatesMap.get(templateName);
    }
}
