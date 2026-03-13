package com.ecommerce.security.multitenancy;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;

/**
 * Routes database connections to tenant-specific schemas.
 * Spring JPA calls determineCurrentLookupKey() before each query.
 * The key maps to a DataSource registered in the parent map.
 */
@Slf4j
public class TenantAwareRoutingDataSource extends AbstractRoutingDataSource {

    private static final String DEFAULT_TENANT = "public";

    @Override
    protected Object determineCurrentLookupKey() {
        String tenantId = TenantContext.getCurrentTenant();

        if (tenantId == null || tenantId.isBlank()) {
            log.debug("No tenant in context — using default schema: {}", DEFAULT_TENANT);
            return DEFAULT_TENANT;
        }

        log.debug("Routing to tenant schema: {}", tenantId);
        return tenantId;
    }
}
