package com.ecommerce.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfile {

    private String id;
    private String email;
    private String firstName;
    private String lastName;
    private String tenantId;
    private Set<String> roles;
    private Set<String> permissions;
    private String status;
    private boolean twoFactorEnabled;
    private Instant lastLoginAt;
}
