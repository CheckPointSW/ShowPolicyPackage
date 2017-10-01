package com.checkpoint.mgmt_api.objects;

import org.json.simple.JSONObject;

/**
 * This class represents a html page of objects of a package, and counts for each object's type how many objects exist.
 */
public class ObjectsInUse
{
    private JSONObject allTypes;
    private String htmlObjectsFileName;

    /**
     *This function counts the number of appearance of each type in a given objects collection
     * @param packageName the package's name
     * @param allTypes the number of time object type appears
     */
    public ObjectsInUse(String packageName, JSONObject allTypes)
    {
        htmlObjectsFileName = packageName+"_objects.html";
        this.allTypes = allTypes;
    }

    /**
     * Util function.
     * Creates a json object that represent the class.
     *
     * @return The {@link JSONObject} that represent the class
     */
    public JSONObject toJson(){

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("types", allTypes);
        jsonObject.put("htmlObjectsFileName",htmlObjectsFileName );

        return jsonObject;
    }

}
