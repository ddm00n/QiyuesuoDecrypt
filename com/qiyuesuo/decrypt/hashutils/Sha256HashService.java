package com.qiyuesuo.decrypt.hashutils;

import net.qiyuesuo.common.lang.ByteUtils;

public class Sha256HashService
        implements HashService {
    public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
    public static final int DEFAULT_HASH_ITERATIONS = 12016;
    private final String algorithmName;
    private final int iterations;
    private final String salt;

    public Sha256HashService() {
        this.salt = null;
        this.algorithmName = DEFAULT_HASH_ALGORITHM;
        this.iterations = 12016;
    }

    @Override
    public SimpleHash computeHash(Object source) {
        byte[] sourceBytes = ByteUtils.toBytes((Object)source);
        return new SimpleHash(DEFAULT_HASH_ALGORITHM, sourceBytes, 12016);
    }

    @Override
    public Hash parseHash(byte[] storedBytes) {
        SimpleHash simpleHash = new SimpleHash(DEFAULT_HASH_ALGORITHM);
        simpleHash.setIterations(12016);
        simpleHash.setBytes(storedBytes);
        return simpleHash;
    }

    protected int getIterations() {
        return this.iterations;
    }

    public String getAlgorithmName() {
        return this.algorithmName;
    }

    public String getSalt() {
        return this.salt;
    }
}
