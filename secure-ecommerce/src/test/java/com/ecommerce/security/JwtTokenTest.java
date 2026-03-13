package com.ecommerce.security;

import com.ecommerce.security.config.JwtConfig;
import com.ecommerce.security.jwt.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JWT Token Provider Tests")
class JwtTokenTest {

    private JwtTokenProvider tokenProvider;
    private JwtConfig jwtConfig;

    @BeforeEach
    void setUp() {
        jwtConfig = new JwtConfig();
        jwtConfig.setSecret("404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970");
        jwtConfig.setAccessTokenExpiry(900000L);
        jwtConfig.setRefreshTokenExpiry(604800000L);
        jwtConfig.setIssuer("test-issuer");

        tokenProvider = new JwtTokenProvider(jwtConfig);
    }

    @Test
    @DisplayName("Should generate a valid access token")
    void generateAccessToken_ValidInput_ReturnsToken() {
        Authentication auth = createAuthentication("user@test.com", "ROLE_CUSTOMER");

        String token = tokenProvider.generateAccessToken(auth, "tenant-1");

        assertThat(token).isNotNull().isNotBlank();
        assertThat(tokenProvider.validateToken(token)).isTrue();
    }

    @Test
    @DisplayName("Should extract correct username from token")
    void extractUsername_ValidToken_ReturnsUsername() {
        Authentication auth = createAuthentication("user@test.com", "ROLE_CUSTOMER");
        String token = tokenProvider.generateAccessToken(auth, "tenant-1");

        assertThat(tokenProvider.extractUsername(token)).isEqualTo("user@test.com");
    }

    @Test
    @DisplayName("Should extract correct tenant ID from token")
    void extractTenantId_ValidToken_ReturnsTenantId() {
        Authentication auth = createAuthentication("user@test.com", "ROLE_CUSTOMER");
        String token = tokenProvider.generateAccessToken(auth, "tenant-123");

        assertThat(tokenProvider.extractTenantId(token)).isEqualTo("tenant-123");
    }

    @Test
    @DisplayName("Should extract roles from token")
    void extractRoles_ValidToken_ReturnsRoles() {
        Authentication auth = createAuthentication("admin@test.com", "ROLE_ADMIN");
        String token = tokenProvider.generateAccessToken(auth, "tenant-1");

        assertThat(tokenProvider.extractRoles(token)).contains("ROLE_ADMIN");
    }

    @Test
    @DisplayName("Each token should have a unique jti")
    void generateTokens_MultipleTokens_UniqueJtis() {
        Authentication auth = createAuthentication("user@test.com", "ROLE_CUSTOMER");

        String token1 = tokenProvider.generateAccessToken(auth, "tenant-1");
        String token2 = tokenProvider.generateAccessToken(auth, "tenant-1");

        assertThat(tokenProvider.extractTokenId(token1))
            .isNotEqualTo(tokenProvider.extractTokenId(token2));
    }

    @Test
    @DisplayName("Should reject tampered token")
    void validateToken_TamperedToken_ReturnsFalse() {
        String tamperedToken = "eyJhbGciOiJIUzI1NiJ9.tampered.signature";

        assertThat(tokenProvider.validateToken(tamperedToken)).isFalse();
    }

    @Test
    @DisplayName("Should reject null/empty token")
    void validateToken_EmptyToken_ReturnsFalse() {
        assertThat(tokenProvider.validateToken("")).isFalse();
        assertThat(tokenProvider.validateToken(null)).isFalse();
    }

    @Test
    @DisplayName("Should generate a refresh token")
    void generateRefreshToken_ValidInput_ReturnsToken() {
        String token = tokenProvider.generateRefreshToken("user@test.com", "tenant-1");

        assertThat(token).isNotNull().isNotBlank();
        assertThat(tokenProvider.validateToken(token)).isTrue();
        assertThat(tokenProvider.extractUsername(token)).isEqualTo("user@test.com");
    }

    private Authentication createAuthentication(String email, String role) {
        return new UsernamePasswordAuthenticationToken(
            email,
            null,
            List.of(new SimpleGrantedAuthority(role))
        );
    }
}
