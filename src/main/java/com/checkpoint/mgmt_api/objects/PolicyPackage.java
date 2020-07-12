package com.checkpoint.mgmt_api.objects;

import com.checkpoint.mgmt_api.examples.ShowPackageConfiguration;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.util.*;

/**
 * This class represents a Package: name, access layer, threat layer, nat layer, objects and gateways that
 * one of the policies of the current package install on.
 */
public class PolicyPackage
{
    private String        packageName;
    private List<Layer>   accessLayers;
    private List<Layer>   threatLayers;
    private Layer         natLayer;
    private ObjectsInUse  objects;

    //The gateways and servers that the policy package install on
    private Map<String,String> gatewayAndServer;

    //The name of the html page of the gateway objects
    private String htmlGatewaysFileName;

    public PolicyPackage(String name, List<Layer> access, List<Layer> threat, Layer nat ,
                         JSONObject allTypes) {

        packageName          = name;
        accessLayers         = access;
        threatLayers         = threat;
        natLayer             = nat;
        objects              = new ObjectsInUse(name, allTypes);
        gatewayAndServer     = new HashMap<>();
        htmlGatewaysFileName = packageName+"_gateway_objects.html";
    }

    /**
     *  Add new gateway to the collection
     *
     * @param gateway
     */
    public void setGatewayAndServer(GatewayAndServer gateway){
        gatewayAndServer.put(gateway.getUid(),gateway.getName());
    }
    /**
     * Util function.
     * Creates a json object that represent the class.
     *
     * @return The {@link JSONObject} that represent the class
     */
    public JSONObject toJson(){

        JSONObject jsonObject = new JSONObject();

        jsonObject.put("packageName",packageName);

        if(ShowPackageConfiguration.INSTANCE.showAccessPolicyFlag()){
            JSONArray accessLayersArray = new  JSONArray();
            for (Layer access : accessLayers){
                accessLayersArray.add(access.toJson());
            }
            jsonObject.put("accessLayers",accessLayersArray);
        }else{
            jsonObject.put("accessLayers", Collections.emptyList());
        }

        if(ShowPackageConfiguration.INSTANCE.showThreatPolicyFlag()){
            JSONArray threatLayersArray = new  JSONArray();
            for (Layer threat : threatLayers){
                threatLayersArray.add(threat.toJson());
            }
            jsonObject.put("threatLayers",threatLayersArray);
        }else{
            jsonObject.put("threatLayers", Collections.emptyList());
        }

        if(ShowPackageConfiguration.INSTANCE.showNatPolicyFlag()) {
            jsonObject.put("natLayer", natLayer.toJson());
        }
        else {
            jsonObject.put("natLayer", Collections.emptyList());
        }

        jsonObject.put("objects",objects.toJson());

        JSONArray gatewaysAndServers = new  JSONArray();
        for (String uid : gatewayAndServer.keySet()){
            JSONObject object = new JSONObject();
            object.put("uid" , uid);
            object.put("name", gatewayAndServer.get(uid));
            gatewaysAndServers.add(object);
        }
        jsonObject.put("gatewayAndServerList",gatewaysAndServers);
        jsonObject.put("htmlGatewaysFileName", htmlGatewaysFileName);
        return jsonObject;
    }
}
