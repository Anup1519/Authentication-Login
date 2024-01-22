package com.demo.Authentication.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "app.token.jwt")
public class TokenProperty {
	
	private long expires;
	
	private String privateKey;
	
	private String publicKey;

}
