package com.qiyuesuo.decrypt;

import com.qiyuesuo.decrypt.hashutils.ConfidentialImpl;
import com.qiyuesuo.decrypt.hashutils.Confidential;
import com.qiyuesuo.decrypt.hashutils.Sha256HashService;
import com.qiyuesuo.decrypt.rsautils.RSAUtils;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class CryptoTool {

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            return;
        }

        switch (args[0]) {
            case "-decrypt":
                handleDecrypt(args);
                break;
            case "-hash":
                if (args.length < 2) {
                    System.out.println("Missing string to hash.");
                } else {
                    Sha256HashService sha256HashService = new Sha256HashService();
                    System.out.println("com.qiyuesuo.decrypt.hashutils.Hash Result: " + sha256HashService.computeHash(args[1]).toHex());
                }
                break;
            default:
                printUsage();
        }
    }

    private static void handleDecrypt(String[] args) {
        boolean useDb = false;
        boolean useUser = false;
        boolean webPwd = false;
        String salt = null;
        String ciphertext = null;

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "-db":
                    useDb = true;
                    break;
                case "-web":
                    webPwd = true;
                    break;
                case "-user":
                    useUser = true;
                    break;
                case "-salt":
                    if (i + 1 < args.length) {
                        salt = args[++i];
                    } else {
                        System.out.println("Missing salt value after -salt");
                        return;
                    }
                    break;
                default:
                    ciphertext = args[i];
            }
        }

        if (ciphertext == null) {
            System.out.println("Missing ciphertext.");
            return;
        }

        if (useDb) {
            System.out.println("[DB] Decrypted: " + decryptWithJasypt(ciphertext));
        } else if (useUser) {
            if (salt == null) {
                System.out.println("Missing -salt for user decryption");
                return;
            }
            Confidential confidential = new ConfidentialImpl();
            confidential.setSalt(salt);
            System.out.println("[USER] Decrypted: " + confidential.decrypt(ciphertext));
        } else if (webPwd) {
            System.out.printf("[WEB] Decrypted: %s\n", RSAUtils.decryptByDefaultPrivateKey(ciphertext));

        } else {
            System.out.println("Specify either -db or -user for decryption.");
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  -decrypt [-db|-user|-web -salt <salt>] <ciphertext>");
        System.out.println("  -hash <plaintext>");
    }

    public static String decryptWithJasypt(String ciphertext) {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword("qiyuesuo@2019");
        config.setAlgorithm("PBEWithMD5AndDES");
        config.setKeyObtentionIterations("1000");
        config.setPoolSize("1");
        config.setProviderName("SunJCE");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setIvGeneratorClassName("org.jasypt.salt.NoOpIVGenerator");
        config.setStringOutputType("base64");
        encryptor.setConfig(config);
        if (ciphertext.startsWith("QYS@")) {
            ciphertext = ciphertext.substring("QYS@".length());
        }
        return encryptor.decrypt(ciphertext);
    }

    public static String decryptWithAES(String encrypted, String salt) {
        try {
            byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
            PBEKeySpec keySpec = new PBEKeySpec("qiyuesuo".toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey key = keyFactory.generateSecret(keySpec);
            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
            PBEParameterSpec parameterSpec = new PBEParameterSpec(saltBytes, 1000);
            pbeCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            byte[] decoded = Base64.getDecoder().decode(encrypted);
            byte[] decrypted = pbeCipher.doFinal(decoded);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "[ERROR] " + e.getMessage();
        }
    }
}

