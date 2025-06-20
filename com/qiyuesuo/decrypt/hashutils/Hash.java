package com.qiyuesuo.decrypt.hashutils;

public interface Hash {
    public String getAlgorithmName();

    public byte[] getSalt();

    public int getIterations();

    public byte[] getBytes();

    public String toHex();
}
