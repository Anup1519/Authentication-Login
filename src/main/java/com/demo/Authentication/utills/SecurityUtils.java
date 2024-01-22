package com.demo.Authentication.utills;

import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecurityUtils {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityUtils.class);
    private static String key = "3DLakeRawcubesUS"; // 128 bit key
    private static String initVector = "1857195720572157"; // 16 bytes IV

    public static String aesEncrypt(String password) throws Exception {
        String encryptedPassword = null;
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(password.getBytes());
            encryptedPassword = Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            LOG.error("Error while encrypting : " + ex.getMessage());
            throw ex;
        }
        return encryptedPassword;
    }

    public static String aesDecrypt(String encryptedPassword) throws Exception {
        String decryptedPassword = null;
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decodeBase64(encryptedPassword));
            decryptedPassword = new String(original);
        } catch (Exception ex) {
            LOG.error("Error while decrypting : " + ex.getMessage());
            throw ex;
        }
        return decryptedPassword;
    }
}
