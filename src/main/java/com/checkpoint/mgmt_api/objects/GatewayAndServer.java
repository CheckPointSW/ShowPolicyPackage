package com.checkpoint.mgmt_api.objects;

import org.json.simple.JSONObject;

/**
 *This class represents gateways or servers: name, uid, access policy, threat policy.
 */
public class GatewayAndServer
{
    private String name;
    private String uid;
    private String accessPolicy;
    private String threatPolicy;
    private JSONObject gatewayObject;

    /**
     * Get the name of the gateway or server
     *
     * @return The name
     */
    public String getName()
    {
        return name;
    }

    /**
     * Set The gateway or server name
     *
     * @param name
     */
    public void setName(String name)
    {
        this.name = name;
    }

    /**
     * Get the uid.
     *
     * @return The uid
     */
    public String getUid()
    {
        return uid;
    }

    /**
     * Set the uid.
     *
     * @param uid
     */
    public void setUid(String uid)
    {
        this.uid = uid;
    }

    /**
     * Get access policy
     *
     * @return The access Policy
     */
    public String getAccessPolicy()
    {
        return accessPolicy;
    }

    /**
     * Set the access policy
     *
     * @param accessPolicy
     */
    public void setAccessPolicy(String accessPolicy)
    {
        this.accessPolicy = accessPolicy;
    }

    /**
     * Set the gateway object
     *
     * @param gatewayObject
     */
    public void setGatewayObject(JSONObject gatewayObject){
       this.gatewayObject = gatewayObject;
    }

    /**
     * get the gateway object
     *
     * @return the gateway in a json format
     */
    public JSONObject getGatewayObject(){
        return gatewayObject;
    }
    /**
     * Get the threat policy.
     *
     * @return The threat policy
     */
    public String getThreatPolicy()
    {
        return threatPolicy;
    }

    /**
     * Set the threat policy.
     *
     * @param threatPolicy
     */
    public void setThreatPolicy(String threatPolicy)
    {
        this.threatPolicy = threatPolicy;
    }

}
