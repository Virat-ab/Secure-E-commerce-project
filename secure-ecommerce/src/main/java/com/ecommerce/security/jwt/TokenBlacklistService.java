package com.ecommerce.security.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Manages token revocation via Redis.
 * Blacklisted token IDs are stored with TTL matching token expiry
 * so Redis auto-cleans expired entries.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private static final String BLACKLIST_PREFIX = "blacklist:token:";

    private final StringRedisTemplate redisTemplate;
    private final JwtTokenProvider tokenProvider;

    /**
     * Blacklist a token by its jti (JWT ID).
     * TTL is set to remaining token lifetime so Redis auto-expires it.
     */
    public void blacklist(String token) {
        try {
            String tokenId = tokenProvider.extractTokenId(token);
            long ttlMillis = tokenProvider.getExpirationMillis(token);

            if (ttlMillis > 0) {
                redisTemplate.opsForValue().set(
                    BLACKLIST_PREFIX + tokenId,
                    "revoked",
                    ttlMillis,
                    TimeUnit.MILLISECONDS
                );
                log.info("Token blacklisted: {}", tokenId);
            }
        } catch (Exception ex) {
            log.error("Failed to blacklist token: {}", ex.getMessage());
        }
    }

    /**
     * Check if a token ID is blacklisted.
     */
    public boolean isBlacklisted(String tokenId) {
        return Boolean.TRUE.equals(
            redisTemplate.hasKey(BLACKLIST_PREFIX + tokenId)
        );
    }

    /**
     * Blacklist all tokens for a user (logout all devices).
     * Stores a user-level revocation timestamp; tokens issued before
     * this timestamp are considered invalid.
     */
    public void blacklistAllUserTokens(String username) {
        String key = "blacklist:user:" + username;
        redisTemplate.opsForValue().set(
            key,
            String.valueOf(System.currentTimeMillis()),
            30, // Keep for 30 days (max refresh token lifetime)
            TimeUnit.DAYS
        );
        log.info("All tokens revoked for user: {}", username);
    }

    /**
     * Get timestamp of global revocation for a user (if set).
     */
    public Long getUserRevocationTimestamp(String username) {
        String value = redisTemplate.opsForValue().get("blacklist:user:" + username);
        return value != null ? Long.parseLong(value) : null;
    }
}
