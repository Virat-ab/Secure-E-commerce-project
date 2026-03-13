package com.ecommerce.controller;

import com.ecommerce.model.dto.JwtResponse;
import com.ecommerce.model.dto.LoginRequest;
import com.ecommerce.security.audit.SecurityAudit;
import com.ecommerce.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/login
     * Authenticate with email + password, returns JWT pair.
     */
    @PostMapping("/login")
    @SecurityAudit(action = "USER_LOGIN")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * POST /api/auth/refresh
     * Exchange a valid refresh token for a new access token.
     * Old refresh token is immediately blacklisted (rotation).
     */
    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
    }

    /**
     * POST /api/auth/logout
     * Revoke current access + refresh token via Redis blacklist.
     */
    @PostMapping("/logout")
    @SecurityAudit(action = "USER_LOGOUT")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader("Authorization") String bearerToken,
            @RequestParam(required = false, defaultValue = "false") boolean allDevices) {
        String token = bearerToken.replace("Bearer ", "");
        authService.logout(token, allDevices);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    /**
     * POST /api/auth/reset-password
     * Send password reset email with time-limited token.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> requestPasswordReset(
            @RequestBody Map<String, String> body) {
        authService.requestPasswordReset(body.get("email"));
        // Always return 200 to prevent email enumeration
        return ResponseEntity.ok(Map.of("message",
            "If an account exists, a reset email has been sent"));
    }

    /**
     * POST /api/auth/reset-password/confirm
     * Confirm password reset with token and new password.
     */
    @PostMapping("/reset-password/confirm")
    @SecurityAudit(action = "PASSWORD_RESET")
    public ResponseEntity<Map<String, String>> confirmPasswordReset(
            @RequestBody Map<String, String> body) {
        authService.confirmPasswordReset(body.get("token"), body.get("newPassword"));
        return ResponseEntity.ok(Map.of("message", "Password reset successfully"));
    }

    /**
     * POST /api/auth/register
     * Register a new user account (requires email verification).
     */
    @PostMapping("/register")
    @SecurityAudit(action = "USER_REGISTER")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody LoginRequest request) {
        authService.register(request);
        return ResponseEntity.ok(Map.of("message",
            "Registration successful. Please verify your email."));
    }

    /**
     * GET /api/auth/verify-email
     * Confirm email address via token link.
     */
    @GetMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(Map.of("message", "Email verified successfully"));
    }
}
