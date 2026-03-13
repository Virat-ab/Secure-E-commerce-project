package com.ecommerce.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "tenants")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(unique = true, nullable = false)
    private String name;

    @Column(unique = true, nullable = false)
    private String subdomain;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE"; // ACTIVE, SUSPENDED, TRIAL, ARCHIVED

    @Column(nullable = false)
    @Builder.Default
    private String plan = "STANDARD"; // STANDARD, PROFESSIONAL, ENTERPRISE

    private String adminEmail;
    private int maxUsers;
    private String rateLimitTier;  // LOW, MEDIUM, HIGH

    private boolean twoFactorRequired;

    private Instant createdAt;
    private Instant updatedAt;

    @PrePersist
    public void prePersist() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    public void preUpdate() {
        updatedAt = Instant.now();
    }
}
