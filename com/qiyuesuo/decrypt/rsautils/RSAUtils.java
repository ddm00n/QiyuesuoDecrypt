package com.qiyuesuo.decrypt.rsautils;

import java.nio.charset.StandardCharsets;

import net.qiyuesuo.common.crypt.Base64Utils;
import net.qiyuesuo.common.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSAUtils {
    private static final String PRIVKEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALCMObUdcPDxAflm0YxAiXaH8jwT5yE5ADxpDzEJH/5oedE5o39lTlWZ3ZnPuDpwBpxH0FKbrT6JIJi28QYkqXRaq9s8YmRzy152M0XVCqBaqSS4TpR2DDY6QQokLEODo+sCeJHsJzSKj0bxtbg/wkMmNJttp+8w8MMVtVVRYnHHAgMBAAECgYAOLuW/8CKPqL0A3Uq+WrzwYdGLFApAeATV1Zbb2KDSXnBS56+D346gf+D2p2Jkh3VwfrB0wn7zhC6zNhc86BsY1K6Q7xU8b7asDBqki48H3ExuxjEosEqUdLf9p9pPBCPI3I4CN/EZPEoFjNRNi5ZX/CY4iaOgsXPHEkcxuW3GQQJBAOBo9UpXesZYCsmuuGN5SOy6tXI613NUBvXKXkxBil3ZOqozlaSjv5NSQb2zLeh2DcYfecumfgn04rNM/pLeDmECQQDJZnXWg4VrXdjc9hqu/8rkmxdhsr3ERkX1uKJrDUB+AOdFs6mS9gEHnJ70zqQ2ucbhQ4htulbLc9pBVL5gy+EnAkEArdhhfa/7SsBVyxvxeA4zMkEJ4242Df/gTHTzTDvRxxZL3iKMILlB5gzpJN40CEu8K+miXuOh7HCrVp+k733awQJBAMDkERhS/wXF7F40l3nkIz6wC8TWnEnPxFGDdItzNcF4vAhV+qN2WaYgq11sTHrdk01MkO4G+foCC5dmwq+SlSECQGm58ReqUTRDAKl32VX0vEdVvOj2getVxW6jQjJFiGj8iNDfK+DpiLfns3YjwSlWHGxHz1S6/lQ+58+M+fEyvUs=";
    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwjDm1HXDw8QH5ZtGMQIl2h/I8E+chOQA8aQ8xCR/+aHnROaN/ZU5Vmd2Zz7g6cAacR9BSm60+iSCYtvEGJKl0WqvbPGJkc8tedjNF1QqgWqkkuE6Udgw2OkEKJCxDg6PrAniR7Cc0io9G8bW4P8JDJjSbbafvMPDDFbVVUWJxxwIDAQAB";
    private static Logger logger = LoggerFactory.getLogger(RSAUtils.class);

    public static String encryptByPublicKey(String ciphertext, String publicKey) throws Exception {
        byte[] encryptedData = RSA.encryptByPublicKey(ciphertext.getBytes(), publicKey);
        return "{cipher}" + Base64Utils.encode((byte[])encryptedData);
    }

    public static String encryptByDefaultPublicKey(String ciphertext) {
        if (StringUtils.isBlank((CharSequence)ciphertext)) {
            return null;
        }
        try {
            return RSAUtils.encryptByPublicKey(ciphertext, PUBLIC_KEY);
        }
        catch (Exception e) {
            logger.error("\u5bc6\u7801\u52a0\u5bc6\u51fa\u9519", (Throwable)e);
            return null;
        }
    }
    public static String encryptByPrivateKey(String ciphertext, String privateKey) throws Exception {
        byte[] encryptedData = RSA.encryptByPrivateKey(ciphertext.getBytes(), privateKey);
        return "{cipher}" + Base64Utils.encode((byte[])encryptedData);
    }

    public static String encryptByDefaultPrivateKey(String ciphertext) {
        try {
            return RSAUtils.encryptByPrivateKey(ciphertext, PRIVKEY);
        }
        catch (Exception e) {
            logger.error("\u5bc6\u7801\u52a0\u5bc6\u51fa\u9519", (Throwable)e);
            return null;
        }
    }

    public static String decryptByPrivateKey(String ciphertext, String privKey) throws Exception {
        byte[] decryptedData = RSA.decryptByPrivateKey(Base64Utils.decode((String)ciphertext), privKey);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static String decryptByDefaultPrivateKey(String ciphertext) {
        if (StringUtils.isBlank((CharSequence)ciphertext)) {
            return null;
        }
        try {
            if (ciphertext.startsWith("{cipher}")) {
                ciphertext = ciphertext.substring("{cipher}".length());
            }
            return RSAUtils.decryptByPrivateKey(ciphertext, PRIVKEY);
        }
        catch (Exception e) {
            logger.error("\u5bc6\u7801\u89e3\u5bc6\u51fa\u9519", (Throwable)e);
            return null;
        }
    }

    public static String encryptByDefaultPublicKeyV2(String ciphertext) {
        try {
            return RSAUtils.encryptByPublicKeyV2(ciphertext, PUBLIC_KEY);
        }
        catch (Exception e) {
            logger.error("\u5bc6\u7801\u52a0\u5bc6\u51fa\u9519", (Throwable)e);
            return null;
        }
    }

    public static String encryptByPublicKeyV2(String ciphertext, String publicKey) throws Exception {
        byte[] encryptedData = RSA.encryptByPublicKey(ciphertext.getBytes(), publicKey);
        return "{cipher}" + Base64Utils.encode((byte[])encryptedData);
    }
}
