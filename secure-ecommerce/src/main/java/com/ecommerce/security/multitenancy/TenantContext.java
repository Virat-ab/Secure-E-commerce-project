package com.ecommerce.security.multitenancy;

/**
 * Holds the current tenant identifier in a ThreadLocal.
 * Set by TenantFilter at the start of each request and
 * cleared after the request completes.
 */
public class TenantContext {

    private static final ThreadLocal<String> CURRENT_TENANT = new InheritableThreadLocal<>();

    private TenantContext() {}

    public static void setCurrentTenant(String tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    public static String getCurrentTenant() {
        return CURRENT_TENANT.get();
    }

    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
