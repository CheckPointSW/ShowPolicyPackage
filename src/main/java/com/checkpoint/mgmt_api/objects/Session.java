package com.checkpoint.mgmt_api.objects;

import org.json.simple.JSONObject;

public class Session
{
    private String uid;
    private String name;
    private String publishTime;
    private Boolean lastPublishedSession;

    public String getUid()
    {
        return uid;
    }

    public void setUid(String uid)
    {
        this.uid = uid;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getPublishTime()
    {
        return publishTime;
    }

    public void setPublishTime(String publishTime)
    {
        this.publishTime = publishTime;
    }

    public Boolean getLastPublishedSession()
    {
        return lastPublishedSession;
    }

    public void setLastPublishedSession(Boolean lastPublishedSession)
    {
        this.lastPublishedSession = lastPublishedSession;
    }

    public JSONObject toJson(){

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("uid",getUid());
        jsonObject.put("name",getName());
        jsonObject.put("publish-time",getPublishTime());
        jsonObject.put("last-published-session", getLastPublishedSession());

        return jsonObject;
    }


}
