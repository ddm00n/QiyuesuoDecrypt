package com.qiyuesuo.decrypt.hashutils;

public class ConfidentialImpl implements Confidential {
    private String salt;
    @Override
    public String getSalt() {
        return this.salt;
    }

    @Override
    public void setSalt(String var1) {
        this.salt = var1;
    }
}
