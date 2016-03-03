package com.mfilipo.symantec.spe.engine.config;

import com.google.common.base.MoreObjects;
import com.mfilipo.symantec.spe.utils.Validateable;
import com.symantec.scanengine.api.Policy;
import org.springframework.util.Assert;

/**
 * Created by filipowm on 2016-02-25.
 */
public class AntivirusConfig implements Validateable {

    private String host;
    private int port;
    private int readWriteTime = 1000;
    private int failRetryTime = 3000;
    private boolean extendedInfo = true;
    private Policy policy = Policy.SCAN;
    private boolean enabled = true;

    public AntivirusConfig(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public AntivirusConfig(String host, String port) {
        this(host, Integer.valueOf(port));
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public int getReadWriteTime() {
        return readWriteTime;
    }

    public void setReadWriteTime(int readWriteTime) {
        this.readWriteTime = readWriteTime;
    }

    public int getFailRetryTime() {
        return failRetryTime;
    }

    public void setFailRetryTime(int failRetryTime) {
        this.failRetryTime = failRetryTime;
    }

    public boolean isExtendedInfo() {
        return extendedInfo;
    }

    public void setExtendedInfo(boolean extendedInfo) {
        this.extendedInfo = extendedInfo;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("host", host)
                .add("port", port)
                .add("readWriteTime", readWriteTime)
                .add("failRetryTime", failRetryTime)
                .add("extendedInfo", extendedInfo)
                .add("policy", policy)
                .omitNullValues()
                .toString();
    }

    @Override
    public void validate() {
        Assert.hasText(host, "Host must be provided");
        Assert.isTrue(port > 0, "Port must be greater than 0");
        Assert.notNull(policy);
        Assert.isTrue(failRetryTime >= 0, "failRetryTime must be greater or equal 0");
        Assert.isTrue(readWriteTime >= 0, "failRetryTime must be greater or equal 0");
    }
}
