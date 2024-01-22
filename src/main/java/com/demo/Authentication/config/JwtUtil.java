package com.demo.Authentication.config;

import io.jsonwebtoken.Jwts;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class JwtUtil {


    public static String generateToken(Map<String, Object> claim, String username, String privateKey, long expires, List<String> roles) throws NoSuchAlgorithmException, InvalidKeySpecException {
        claim.put("roles", roles);
        return generateToken(claim, username, privateKey, expires);
    }

    private static String generateToken(Map<String, Object> claim, String username, String privateKey, long expires) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Instant now = Instant.now();
        String token = Jwts.builder().claims(claim)
                .subject(username)
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(expires, ChronoUnit.SECONDS)))
                .signWith(KeyUtil.readPrivateKey(privateKey)).compact();
        return token;
    }
}
