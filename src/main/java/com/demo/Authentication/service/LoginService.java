package com.demo.Authentication.service;


import com.demo.Authentication.config.JwtUtil;
import com.demo.Authentication.config.TokenProperty;
import com.demo.Authentication.dto.AuthRequest;
import com.demo.Authentication.dto.TokenResponse;
import io.jsonwebtoken.Jwts;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@Service
public class LoginService {


    public static final Logger Logger = LoggerFactory.getLogger(LoginService.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenProperty tokenProperty;

    public TokenResponse generateToken(AuthRequest authRequest) throws NoSuchAlgorithmException, InvalidKeySpecException {

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken;

        usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

        InetOrgPerson principal = (InetOrgPerson) usernamePasswordAuthenticationToken.getPrincipal();


        // fetch the principal from Ldap and put into Claim

        Map<String, Object> claim = new HashMap<>();
        claim.put("userName",principal.getUsername());
        claim.put("name",principal.getSn()+","+principal.getGivenName());
        claim.put("email",principal.getMail());
        Logger.debug("Claim : "+claim.toString());
        Logger.debug(" getAuthority : "+principal.getAuthorities().toString());
        String token = JwtUtil.generateToken(claim, authRequest.getUsername(), tokenProperty.getPrivateKey(), tokenProperty.getExpires(),
                principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
        Logger.debug("Token : "+token);
        return new TokenResponse("Bearer ",tokenProperty.getExpires(),token);
    }
}
