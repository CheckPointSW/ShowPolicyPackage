package com.checkpoint.mgmt_api.objects;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents the Index html page (main html page).
 */
public class IndexView
{
    private String domain;
    private List<PolicyPackage> policyPackages = new ArrayList<>();

    /**
     *Set the domain name that will appear on the html page.
     *
     * @param domain name
     */
    public void setDomain(String domain)
    {
        this.domain = domain;
    }

    /**
     * Get the packages that will appear on the Index html page.
     *
     * @return The packages name
     */
    public List<PolicyPackage> getPolicyPackages()
    {
        return policyPackages;
    }

    /**
     * Util function.
     * Creates a json object that represent the class.
     *
     * @return The {@link JSONObject} that represent the class
     */
    public JSONObject toJson(){

        JSONObject jsonIndex = new JSONObject();

        jsonIndex.put("domain",domain);
        JSONArray policy = new JSONArray();
        for( PolicyPackage policyPackage : policyPackages){
            if(policyPackage != null) {
                policy.add(policyPackage.toJson());
            }
        }
        jsonIndex.put("policyPackages", policy);

        return jsonIndex;
    }
}
