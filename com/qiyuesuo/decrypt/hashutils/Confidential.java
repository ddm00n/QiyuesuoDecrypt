package com.qiyuesuo.decrypt.hashutils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.function.Function;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.qiyuesuo.common.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public interface Confidential {
    public static final Logger logger = LoggerFactory.getLogger(Confidential.class);
    public static final String BASE_SALT = "abcdefghijklmnopqrstuvwxyz0123456789";
    public static final String BASE_SECRET = "5f6db7ec8325a5e4";
    public static final String ENCRYPT_PREFIX = "{cipher}";
    public static final String SHA256_PREFIX = "{sha256}";
    public static final Function<String, SecretKeySpec> SECRETKEY_SUPPLIER = salt -> {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec baseSecret = new SecretKeySpec(BASE_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(baseSecret);
            return new SecretKeySpec(mac.doFinal(salt.getBytes(StandardCharsets.UTF_8)), "AES");
        }
        catch (Exception e) {
            throw new ConfidentialException(e);
        }
    };

    public static String generateSalt() {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; ++i) {
            int number = random.nextInt(BASE_SALT.length());
            sb.append(BASE_SALT.charAt(number));
        }
        return sb.toString();
    }

    default public String encrypt(String data) {
        if (StringUtils.isBlank((CharSequence)data)) {
            return data;
        }
        if (data.startsWith(ENCRYPT_PREFIX)) {
            return data;
        }
        String salt = this.getSalt();
        if (StringUtils.isBlank((CharSequence)salt)) {
            salt = Confidential.generateSalt();
            this.setSalt(salt);
        }
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(1, SECRETKEY_SUPPLIER.apply(salt));
            return ENCRYPT_PREFIX + new String(Base64.getEncoder().encode(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
        }
        catch (Exception e) {
            logger.error("\u52a0\u5bc6\u5931\u8d25\uff0cdata:{}, salt:{}", (Object)data, (Object)salt);
            if (logger.isDebugEnabled()) {
                logger.debug("\u52a0\u5bc6\u5931\u8d25\uff0cdata:{}, salt:{}", new Object[]{data, salt, e});
            }
            return data;
        }
    }

    default public String decrypt(String data) {
        if (StringUtils.isBlank((CharSequence)data)) {
            return data;
        }
        if (!data.startsWith(ENCRYPT_PREFIX)) {
            return data;
        }
        String salt = this.getSalt();
        if (StringUtils.isBlank((CharSequence)salt)) {
            return data;
        }
        try {
            data = data.substring(ENCRYPT_PREFIX.length());
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(2, SECRETKEY_SUPPLIER.apply(salt));
            byte[] result = cipher.doFinal(Base64.getDecoder().decode(data.getBytes(StandardCharsets.UTF_8)));
            return new String(result, StandardCharsets.UTF_8);
        }
        catch (Exception e) {
            logger.error("\u89e3\u5bc6\u5931\u8d25\uff0cdata:{}, salt:{}", (Object)data, (Object)salt);
            if (logger.isDebugEnabled()) {
                logger.debug("\u89e3\u5bc6\u5931\u8d25\uff0cdata:{}, salt:{}", new Object[]{data, salt, e});
            }
            return data;
        }
    }

    @JsonIgnore
    public String getSalt();

    public void setSalt(String var1);

    public static String hide(String data, int begin, int end) {
        if (data == null || data.trim().isEmpty()) {
            return data;
        }
        if (begin < 0 || end < 0) {
            throw new ConfidentialException("");
        }
        if (data.length() - 1 < begin) {
            return data;
        }
        if (data.length() - 1 < end) {
            end = data.length() - 1;
        }
        if (begin > end) {
            return data;
        }
        String prefix = begin == 0 ? "" : data.substring(0, begin);
        String suffix = end == data.length() - 1 ? "" : data.substring(end);
        return prefix + "*****" + suffix;
    }
}
