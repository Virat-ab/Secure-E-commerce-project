package com.ecommerce.security.audit;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "security_events",
       indexes = {
           @Index(name = "idx_event_username", columnList = "username"),
           @Index(name = "idx_event_tenant", columnList = "tenantId"),
           @Index(name = "idx_event_timestamp", columnList = "timestamp")
       })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String action;

    @Column(nullable = false)
    private String outcome; // SUCCESS | FAILURE

    private String username;
    private String tenantId;
    private String ipAddress;
    private String errorMessage;

    @Column(nullable = false)
    private Instant timestamp;

    @PrePersist
    public void prePersist() {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
