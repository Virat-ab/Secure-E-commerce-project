package com.ecommerce.security.multitenancy;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Resolves the current tenant from:
 * 1. X-Tenant-ID request header (highest priority)
 * 2. Subdomain (e.g. acme.yourdomain.com → "acme")
 * 3. Falls back to null (public schema)
 *
 * Runs before JWT filter so TenantContext is set for token validation.
 */
@Component
@Order(1)
@Slf4j
public class TenantFilter extends OncePerRequestFilter {

    private static final String TENANT_HEADER = "X-Tenant-ID";
    private static final String BASE_DOMAIN = "yourdomain.com";

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String tenantId = resolveTenantId(request);
            if (StringUtils.hasText(tenantId)) {
                TenantContext.setCurrentTenant(tenantId);
                log.debug("Tenant resolved: {}", tenantId);
            }
            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private String resolveTenantId(HttpServletRequest request) {
        // 1. Check header first
        String headerTenant = request.getHeader(TENANT_HEADER);
        if (StringUtils.hasText(headerTenant)) {
            return sanitize(headerTenant);
        }

        // 2. Try subdomain extraction
        String serverName = request.getServerName();
        if (serverName != null && serverName.endsWith("." + BASE_DOMAIN)) {
            String subdomain = serverName.substring(0, serverName.indexOf('.'));
            if (!subdomain.isEmpty() && !"www".equals(subdomain)) {
                return sanitize(subdomain);
            }
        }

        return null;
    }

    /**
     * Sanitize tenant ID to prevent injection attacks.
     * Only allow alphanumeric characters and hyphens.
     */
    private String sanitize(String tenantId) {
        if (tenantId == null) return null;
        String clean = tenantId.replaceAll("[^a-zA-Z0-9\\-]", "");
        return clean.isEmpty() ? null : clean.toLowerCase();
    }
}
