package com.ecommerce.service;

import com.ecommerce.exception.AccountLockedException;
import com.ecommerce.exception.InvalidTokenException;
import com.ecommerce.model.dto.JwtResponse;
import com.ecommerce.model.dto.LoginRequest;
import com.ecommerce.model.dto.UserProfile;
import com.ecommerce.model.entity.User;
import com.ecommerce.model.enums.AuthProvider;
import com.ecommerce.model.enums.UserStatus;
import com.ecommerce.repository.UserRepository;
import com.ecommerce.security.jwt.JwtTokenProvider;
import com.ecommerce.security.jwt.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final TokenBlacklistService blacklistService;
    private final UserRepository userRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.security.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${app.security.lock-duration-minutes:30}")
    private int lockDurationMinutes;

    // ─── Login ───────────────────────────────────────────────────────────────

    @Transactional
    public JwtResponse login(LoginRequest request) {
        User user = userRepository
            .findByEmailAndTenantId(request.getEmail(), request.getTenantId())
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        // Check account lock
        if (user.isLocked()) {
            throw new AccountLockedException("Account locked until " + user.getLockedUntil());
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
                )
            );

            // Reset failed attempts on success
            user.setFailedLoginAttempts(0);
            user.setLastLoginAt(Instant.now());
            userRepository.save(user);

            String accessToken = tokenProvider.generateAccessToken(
                authentication, request.getTenantId());

            String refreshToken = request.isRememberMe()
                ? tokenProvider.generateRememberMeToken(request.getEmail(), request.getTenantId())
                : tokenProvider.generateRefreshToken(request.getEmail(), request.getTenantId());

            UserProfile profile = userService.getUserProfile(request.getEmail());

            return JwtResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(900) // 15 minutes in seconds
                .user(profile)
                .build();

        } catch (BadCredentialsException ex) {
            handleFailedLogin(user);
            throw ex;
        }
    }

    private void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= maxFailedAttempts) {
            user.setLockedUntil(Instant.now().plus(lockDurationMinutes, ChronoUnit.MINUTES));
            log.warn("Account locked due to {} failed attempts: {}", attempts, user.getEmail());
        }

        userRepository.save(user);
    }

    // ─── Refresh Token ───────────────────────────────────────────────────────

    @Transactional
    public JwtResponse refreshToken(String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        String tokenId = tokenProvider.extractTokenId(refreshToken);
        if (blacklistService.isBlacklisted(tokenId)) {
            throw new InvalidTokenException("Refresh token has been revoked");
        }

        // Blacklist the old refresh token (rotation)
        blacklistService.blacklist(refreshToken);

        String username = tokenProvider.extractUsername(refreshToken);
        String tenantId = tokenProvider.extractTenantId(refreshToken);

        var userDetails = userService.loadUserByUsername(username);
        var authentication = new UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());

        String newAccessToken = tokenProvider.generateAccessToken(authentication, tenantId);
        String newRefreshToken = tokenProvider.generateRefreshToken(username, tenantId);

        return JwtResponse.builder()
            .accessToken(newAccessToken)
            .refreshToken(newRefreshToken)
            .expiresIn(900)
            .build();
    }

    // ─── Logout ──────────────────────────────────────────────────────────────

    public void logout(String accessToken, boolean allDevices) {
        blacklistService.blacklist(accessToken);

        if (allDevices) {
            String username = tokenProvider.extractUsername(accessToken);
            blacklistService.blacklistAllUserTokens(username);
            log.info("All sessions revoked for user: {}", username);
        }
    }

    // ─── Password Reset ──────────────────────────────────────────────────────

    public void requestPasswordReset(String email) {
        // Implementation: generate token, store in Redis with 24h TTL, send email
        log.info("Password reset requested for: {}", email);
        // TODO: implement email service + token storage
    }

    public void confirmPasswordReset(String token, String newPassword) {
        // Implementation: validate token from Redis, update password, invalidate token
        log.info("Password reset confirmed");
        // TODO: implement password reset confirmation
    }

    // ─── Registration ────────────────────────────────────────────────────────

    @Transactional
    public void register(LoginRequest request) {
        if (userRepository.existsByEmailAndTenantId(
                request.getEmail(), request.getTenantId())) {
            throw new IllegalArgumentException("Email already registered");
        }

        User user = User.builder()
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .tenantId(request.getTenantId())
            .status(UserStatus.PENDING_VERIFICATION)
            .provider(AuthProvider.LOCAL)
            .build();

        userRepository.save(user);
        log.info("User registered: {}", request.getEmail());
        // TODO: send verification email
    }

    public void verifyEmail(String token) {
        // TODO: validate token from Redis, set emailVerifiedAt, activate account
        log.info("Email verification attempted with token: {}", token);
    }
}
