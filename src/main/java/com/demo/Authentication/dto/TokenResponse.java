package com.demo.Authentication.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenResponse {
	
	private String tokenType;
	
	private long expiresIn;
	
	private String token;
}
