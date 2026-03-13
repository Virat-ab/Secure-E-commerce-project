package com.ecommerce.security.jwt;

import com.ecommerce.security.config.JwtConfig;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    private final JwtConfig jwtConfig;

    // ─── Token Generation ───────────────────────────────────────────────────

    public String generateAccessToken(Authentication authentication, String tenantId) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String roles = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

        return buildToken(userDetails.getUsername(), tenantId, roles,
            jwtConfig.getAccessTokenExpiry(), "ACCESS");
    }

    public String generateRefreshToken(String username, String tenantId) {
        return buildToken(username, tenantId, null,
            jwtConfig.getRefreshTokenExpiry(), "REFRESH");
    }

    public String generateRememberMeToken(String username, String tenantId) {
        return buildToken(username, tenantId, null,
            jwtConfig.getRememberMeExpiry(), "REFRESH");
    }

    private String buildToken(String subject, String tenantId, String roles,
                               long expiry, String tokenType) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiry);

        Map<String, Object> claims = new HashMap<>();
        claims.put("tenantId", tenantId);
        claims.put("tokenType", tokenType);
        if (roles != null) {
            claims.put("roles", roles);
        }

        return Jwts.builder()
            .id(UUID.randomUUID().toString())       // jti — unique token ID for blacklisting
            .subject(subject)
            .issuer(jwtConfig.getIssuer())
            .issuedAt(now)
            .expiration(expiryDate)
            .claims(claims)
            .signWith(getSigningKey())
            .compact();
    }

    // ─── Token Validation ───────────────────────────────────────────────────

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException ex) {
            log.warn("JWT token is expired: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.warn("JWT token is unsupported: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.warn("JWT token is malformed: {}", ex.getMessage());
        } catch (SecurityException ex) {
            log.warn("JWT signature is invalid: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.warn("JWT claims string is empty: {}", ex.getMessage());
        }
        return false;
    }

    // ─── Claims Extraction ──────────────────────────────────────────────────

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractTokenId(String token) {
        return extractClaim(token, Claims::getId);
    }

    public String extractTenantId(String token) {
        return extractAllClaims(token).get("tenantId", String.class);
    }

    public String extractRoles(String token) {
        return extractAllClaims(token).get("roles", String.class);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public long getExpirationMillis(String token) {
        Date expiry = extractExpiration(token);
        return expiry.getTime() - System.currentTimeMillis();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtConfig.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
