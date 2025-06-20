package com.qiyuesuo.decrypt.hashutils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import net.qiyuesuo.common.lang.HexUtils;

public class SimpleHash
        implements Hash {
    private static final int DEFAULT_ITERATIONS = 1;
    private final String algorithmName;
    private byte[] bytes;
    private byte[] salt;
    private int iterations;

    public SimpleHash(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public SimpleHash(String algorithmName, byte[] source) {
        this(algorithmName, source, null);
    }

    public SimpleHash(String algorithmName, byte[] source, byte[] salt) {
        this(algorithmName, source, salt, 1);
    }

    public SimpleHash(String algorithmName, byte[] source, int iterations) {
        this(algorithmName, source, null, iterations);
    }

    public SimpleHash(String algorithmName, byte[] source, byte[] salt, int iterations) {
        this.algorithmName = algorithmName;
        this.salt = salt;
        this.iterations = iterations;
        byte[] hashedBytes = this.hash(source, salt, iterations);
        this.setBytes(hashedBytes);
    }

    protected byte[] hash(byte[] bytes) {
        return this.hash(bytes, null, 1);
    }

    protected byte[] hash(byte[] bytes, byte[] salt) {
        return this.hash(bytes, salt, 1);
    }

    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(this.getAlgorithmName());
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        if (salt != null) {
            digest.reset();
            digest.update(salt);
        }
        byte[] hashed = digest.digest(bytes);
        int iterations = hashIterations - 1;
        for (int i = 0; i < iterations; ++i) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return hashed;
    }

    @Override
    public String getAlgorithmName() {
        return this.algorithmName;
    }

    @Override
    public byte[] getSalt() {
        return this.salt;
    }

    @Override
    public int getIterations() {
        return this.iterations;
    }

    @Override
    public byte[] getBytes() {
        return this.bytes;
    }

    @Override
    public String toHex() {
        return HexUtils.encodeToString((byte[])this.getBytes());
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public void setBytes(byte[] computed) {
        this.bytes = computed;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public int hashCode() {
        int prime = 31;
        int result = 1;
        result = 31 * result + Arrays.hashCode(this.bytes);
        return result;
    }

    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash)o;
            return MessageDigest.isEqual(this.getBytes(), other.getBytes());
        }
        return false;
    }
}
