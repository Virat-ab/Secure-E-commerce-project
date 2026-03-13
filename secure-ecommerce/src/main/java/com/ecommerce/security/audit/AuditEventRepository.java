package com.ecommerce.security.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface AuditEventRepository extends JpaRepository<SecurityEvent, Long> {

    Page<SecurityEvent> findByTenantIdOrderByTimestampDesc(String tenantId, Pageable pageable);

    Page<SecurityEvent> findByUsernameAndTenantIdOrderByTimestampDesc(
        String username, String tenantId, Pageable pageable);

    Page<SecurityEvent> findByActionAndTimestampBetween(
        String action, Instant from, Instant to, Pageable pageable);
}
