package com.checkpoint.mgmt_api.objects;

import org.json.simple.JSONObject;

/**
 * This class represents a layer: uid, name, domain, domain type, html file name fo this layer.
 */
public class Layer {

    private String uid;
    private String name;
    private String domain;
    private String domainType;
    private String htmlFileName;

    /**
     * Get the uid of the layer.
     *
     * @return uid
     */
    public String getUid()
    {
        return uid;
    }

    /**
     * Set the uid of the layer.
     *
     * @param uid
     */
    public void setUid(String uid)
    {
        this.uid = uid;
    }

    /**
     * Get layer name.
     *
     * @return The name
     */
    public String getName()
    {
        return name;
    }

    /**
     * Set layer name.
     *
     * @param name
     */
    public void setName(String name)
    {
        this.name = name;
    }

    /**
     * Get domain layer
     *
     * @return The domain
     */
    public String getDomain()
    {
        return domain;
    }

    /**
     * Set the domain layer.
     *
     * @param domain
     */
    public void setDomain(String domain)
    {
        this.domain = domain;
    }

    /**
     * Set domain layer's type.
     *
     * @param domainType
     */
    public void setDomainType(String domainType)
    {
        this.domainType = domainType;
    }

    /**
     * Set html file name of this layer.
     *
     * @param htmlFileName name of layer's html page
     */
    public void setHtmlFileName(String htmlFileName)
    {
        this.htmlFileName = htmlFileName;
    }

    /**
     * Returns HTML file name of this layer
     *
     * @return HTML file name which was created for this layer
     */
    public String getHtmlFileName()
    {
        return htmlFileName;
    }

    /**
     * Util function.
     * Creates a json object that represent the class.
     *
     * @return The {@link JSONObject} that represent the class
     */
    public JSONObject toJson(){

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("uid",uid);
        jsonObject.put("name",name);
        jsonObject.put("domain",domain);
        jsonObject.put("domainType",domainType);
        jsonObject.put("htmlFileName",htmlFileName);

        return jsonObject;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Layer layer = (Layer) o;

        return uid.equals(layer.uid);
    }

    @Override
    public int hashCode()
    {
        return uid.hashCode();
    }
}
