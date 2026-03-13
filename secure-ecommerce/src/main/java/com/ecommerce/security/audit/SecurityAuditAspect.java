package com.ecommerce.security.audit;

import com.ecommerce.security.multitenancy.TenantContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;

/**
 * AOP aspect that intercepts methods annotated with @SecurityAudit
 * and logs security events asynchronously.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityAuditAspect {

    private final AuditEventRepository auditEventRepository;

    @Around("@annotation(securityAudit)")
    public Object auditSecurityEvent(ProceedingJoinPoint joinPoint,
                                      SecurityAudit securityAudit) throws Throwable {
        String username = resolveUsername();
        String tenantId = TenantContext.getCurrentTenant();
        String ipAddress = resolveClientIp();
        String action = securityAudit.action();
        Instant startTime = Instant.now();

        try {
            Object result = joinPoint.proceed();
            saveAuditEvent(username, tenantId, ipAddress, action, "SUCCESS", null);
            return result;
        } catch (Exception ex) {
            saveAuditEvent(username, tenantId, ipAddress, action, "FAILURE", ex.getMessage());
            throw ex;
        }
    }

    @Async
    protected void saveAuditEvent(String username, String tenantId, String ipAddress,
                                   String action, String outcome, String errorMessage) {
        try {
            SecurityEvent event = SecurityEvent.builder()
                .username(username)
                .tenantId(tenantId)
                .ipAddress(ipAddress)
                .action(action)
                .outcome(outcome)
                .errorMessage(errorMessage)
                .timestamp(Instant.now())
                .build();

            auditEventRepository.save(event);

            log.info("AUDIT | action={} | user={} | tenant={} | ip={} | outcome={}",
                action, username, tenantId, ipAddress, outcome);
        } catch (Exception ex) {
            log.error("Failed to save audit event: {}", ex.getMessage());
        }
    }

    private String resolveUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.isAuthenticated())
            ? auth.getName()
            : "anonymous";
    }

    private String resolveClientIp() {
        try {
            ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return "unknown";

            HttpServletRequest request = attrs.getRequest();
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isEmpty()) {
                return forwarded.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        } catch (Exception ex) {
            return "unknown";
        }
    }
}
