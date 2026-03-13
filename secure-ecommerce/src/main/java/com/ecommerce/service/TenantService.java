package com.ecommerce.service;

import com.ecommerce.exception.ResourceNotFoundException;
import com.ecommerce.model.entity.Tenant;
import com.ecommerce.repository.TenantRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class TenantService {

    private final TenantRepository tenantRepository;

    @Transactional
    public Tenant provisionTenant(Map<String, Object> body) {
        String subdomain = (String) body.get("subdomain");

        if (tenantRepository.existsBySubdomain(subdomain)) {
            throw new IllegalArgumentException("Subdomain already taken: " + subdomain);
        }

        Tenant tenant = Tenant.builder()
            .name((String) body.get("name"))
            .subdomain(subdomain)
            .adminEmail((String) body.get("adminEmail"))
            .plan(body.getOrDefault("plan", "STANDARD").toString())
            .maxUsers(body.containsKey("maxUsers") ? (Integer) body.get("maxUsers") : 100)
            .build();

        Tenant saved = tenantRepository.save(tenant);

        // TODO: Create schema, run Flyway migrations for this tenant
        log.info("Tenant provisioned: {} ({})", saved.getName(), saved.getId());

        return saved;
    }

    public Page<Tenant> listTenants(String status, String plan, Pageable pageable) {
        return tenantRepository.findAll(pageable);
    }

    public Tenant getTenant(String id) {
        return tenantRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Tenant not found: " + id));
    }

    @Transactional
    public Tenant updateTenant(String id, Map<String, Object> updates) {
        Tenant tenant = getTenant(id);

        if (updates.containsKey("status"))           tenant.setStatus((String) updates.get("status"));
        if (updates.containsKey("maxUsers"))         tenant.setMaxUsers((Integer) updates.get("maxUsers"));
        if (updates.containsKey("rateLimitTier"))    tenant.setRateLimitTier((String) updates.get("rateLimitTier"));
        if (updates.containsKey("twoFactorRequired"))
            tenant.setTwoFactorRequired((Boolean) updates.get("twoFactorRequired"));

        return tenantRepository.save(tenant);
    }

    @Transactional
    public void suspendTenant(String id) {
        Tenant tenant = getTenant(id);
        tenant.setStatus("SUSPENDED");
        tenantRepository.save(tenant);
        log.warn("Tenant suspended: {}", id);
    }
}
