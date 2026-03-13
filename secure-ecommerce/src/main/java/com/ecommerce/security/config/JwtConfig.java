package com.ecommerce.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtConfig {

    private String secret;
    private long accessTokenExpiry = 900000;       // 15 min
    private long refreshTokenExpiry = 604800000;   // 7 days
    private long rememberMeExpiry = 2592000000L;   // 30 days
    private String issuer = "secure-ecommerce";
}
