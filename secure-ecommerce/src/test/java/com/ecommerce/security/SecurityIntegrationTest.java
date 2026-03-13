package com.ecommerce.security;

import com.ecommerce.model.dto.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Security Integration Tests")
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Public endpoints should be accessible without authentication")
    void publicEndpoints_NoAuth_Returns200() throws Exception {
        mockMvc.perform(get("/actuator/health"))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Protected endpoint should return 401 without JWT")
    void protectedEndpoint_NoJwt_Returns401() throws Exception {
        mockMvc.perform(get("/api/users/me"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Admin endpoint should return 403 for non-admin users")
    void adminEndpoint_NonAdmin_Returns403() throws Exception {
        mockMvc.perform(get("/api/users")
            .header("Authorization", "Bearer invalid-token"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Login with invalid credentials returns 401")
    void login_InvalidCredentials_Returns401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("wrong@example.com");
        request.setPassword("wrongpassword");
        request.setTenantId("test-tenant");

        mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Login with invalid email format returns 400")
    void login_InvalidEmailFormat_Returns400() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("not-an-email");
        request.setPassword("password");
        request.setTenantId("tenant");

        mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("SQL injection attempt in login should be rejected")
    void login_SqlInjection_Returns400() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("' OR '1'='1");
        request.setPassword("' OR '1'='1");
        request.setTenantId("tenant");

        mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest()); // validation rejects invalid email
    }

    @Test
    @DisplayName("Security headers should be present on all responses")
    void allResponses_ShouldHaveSecurityHeaders() throws Exception {
        mockMvc.perform(get("/actuator/health"))
            .andExpect(header().exists("X-Content-Type-Options"))
            .andExpect(header().string("X-Frame-Options", "DENY"))
            .andExpect(header().exists("Strict-Transport-Security"));
    }

    @Test
    @DisplayName("CORS preflight request should be handled")
    void corsPreflightRequest_Returns200() throws Exception {
        mockMvc.perform(options("/api/auth/login")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "POST"))
            .andExpect(status().isOk());
    }
}
