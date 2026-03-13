package com.ecommerce.security.audit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotate any controller/service method to automatically
 * log a security audit event on invocation.
 *
 * Usage:
 *   @SecurityAudit(action = "USER_LOGIN")
 *   public JwtResponse login(...) { ... }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface SecurityAudit {

    /** Human-readable action name stored in the audit log */
    String action();

    /** Optional description for documentation */
    String description() default "";
}
