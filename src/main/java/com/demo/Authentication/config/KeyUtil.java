package com.demo.Authentication.config;

import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class KeyUtil {


    public static PrivateKey readPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return decodePrivateKey(privateKey, SignatureAlgorithm.RS256.getFamilyName());
    }

    private static PrivateKey decodePrivateKey(String privateKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {

        privateKey = removeCertBeginEnd(privateKey);
        //  decode and extract the private key
        byte[] decode = Base64.getDecoder().decode(privateKey);


        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decode);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(keySpec);
    }

    private static String removeCertBeginEnd(String pem) {

        pem = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "");
        pem = pem.replaceAll("-----END PRIVATE KEY-----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        pem = pem.replaceAll("\\\\n", "");
        return pem.trim();
    }
}
