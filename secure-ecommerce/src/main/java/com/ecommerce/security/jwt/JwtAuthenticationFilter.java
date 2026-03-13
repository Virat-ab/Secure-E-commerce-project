package com.ecommerce.security.jwt;

import com.ecommerce.security.multitenancy.TenantContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenProvider tokenProvider;
    private final TokenBlacklistService blacklistService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String jwt = extractJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {

                // Check token blacklist (Redis)
                String tokenId = tokenProvider.extractTokenId(jwt);
                if (blacklistService.isBlacklisted(tokenId)) {
                    log.warn("Blacklisted token used: {}", tokenId);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked");
                    return;
                }

                // Extract claims
                String username = tokenProvider.extractUsername(jwt);
                String tenantId = tokenProvider.extractTenantId(jwt);
                String roles = tokenProvider.extractRoles(jwt);

                // Set tenant context for this request thread
                if (StringUtils.hasText(tenantId)) {
                    TenantContext.setCurrentTenant(tenantId);
                }

                // Build authorities from JWT roles claim (avoids DB hit on every request)
                List<SimpleGrantedAuthority> authorities = List.of();
                if (StringUtils.hasText(roles)) {
                    authorities = Arrays.stream(roles.split(","))
                        .map(String::trim)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                }

                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    var authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        authorities.isEmpty() ? userDetails.getAuthorities() : authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("Authenticated user: {} for tenant: {}", username, tenantId);
                }
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication: {}", ex.getMessage());
        } finally {
            filterChain.doFilter(request, response);
            // Clear tenant context after request completes
            TenantContext.clear();
        }
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/auth/login")
            || path.startsWith("/api/auth/register")
            || path.startsWith("/api/auth/reset-password")
            || path.startsWith("/oauth2/")
            || path.startsWith("/actuator/health");
    }
}
