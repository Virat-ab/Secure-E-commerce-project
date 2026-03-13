package com.ecommerce.controller;

import com.ecommerce.model.entity.Tenant;
import com.ecommerce.security.audit.SecurityAudit;
import com.ecommerce.service.TenantService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/tenants")
@RequiredArgsConstructor
public class TenantController {

    private final TenantService tenantService;

    /**
     * POST /api/tenants
     * Provision a new tenant (creates schema + admin user). Super-admin only.
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityAudit(action = "TENANT_CREATE")
    public ResponseEntity<Tenant> createTenant(@RequestBody Map<String, Object> body) {
        return ResponseEntity.ok(tenantService.provisionTenant(body));
    }

    /**
     * GET /api/tenants
     * List all tenants with pagination. Super-admin only.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<Tenant>> listTenants(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String plan,
            Pageable pageable) {
        return ResponseEntity.ok(tenantService.listTenants(status, plan, pageable));
    }

    /**
     * GET /api/tenants/{id}
     * Get tenant details. Tenant admins can only view their own.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @tenantSecurity.isCurrentTenant(#id)")
    public ResponseEntity<Tenant> getTenant(@PathVariable String id) {
        return ResponseEntity.ok(tenantService.getTenant(id));
    }

    /**
     * PUT /api/tenants/{id}
     * Update tenant configuration. Admin only.
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityAudit(action = "TENANT_UPDATE")
    public ResponseEntity<Tenant> updateTenant(
            @PathVariable String id,
            @RequestBody Map<String, Object> updates) {
        return ResponseEntity.ok(tenantService.updateTenant(id, updates));
    }

    /**
     * POST /api/tenants/{id}/suspend
     * Suspend a tenant (blocks all logins). Super-admin only.
     */
    @PostMapping("/{id}/suspend")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityAudit(action = "TENANT_SUSPEND")
    public ResponseEntity<Map<String, String>> suspendTenant(@PathVariable String id) {
        tenantService.suspendTenant(id);
        return ResponseEntity.ok(Map.of("message", "Tenant suspended"));
    }
}
