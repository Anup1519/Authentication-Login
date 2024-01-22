package com.demo.Authentication.controller;


import com.demo.Authentication.dto.AuthRequest;
import com.demo.Authentication.dto.TokenResponse;
import com.demo.Authentication.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


@RestController
public class LoginController {


    @Autowired
    private LoginService loginService;

    @PostMapping(value = "/login")
    public ResponseEntity<TokenResponse> login(@RequestBody AuthRequest authRequest) throws NoSuchAlgorithmException, InvalidKeySpecException {
        TokenResponse tokenResponse = loginService.generateToken(authRequest);
        return ResponseEntity.ok().body(tokenResponse);
    }


}
