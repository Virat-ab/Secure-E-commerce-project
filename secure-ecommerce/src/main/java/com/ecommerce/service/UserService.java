package com.ecommerce.service;

import com.ecommerce.exception.ResourceNotFoundException;
import com.ecommerce.model.dto.UserProfile;
import com.ecommerce.model.entity.Role;
import com.ecommerce.model.entity.User;
import com.ecommerce.model.enums.UserStatus;
import com.ecommerce.repository.RoleRepository;
import com.ecommerce.repository.UserRepository;
import com.ecommerce.security.multitenancy.TenantContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    // ─── UserDetailsService (required by Spring Security) ───────────────────

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        String tenantId = TenantContext.getCurrentTenant();

        User user = userRepository.findByEmailAndTenantId(email, tenantId)
            .orElseThrow(() -> new UsernameNotFoundException(
                "User not found: " + email + " in tenant: " + tenantId));

        if (user.isLocked()) {
            throw new UsernameNotFoundException("Account is locked until " + user.getLockedUntil());
        }

        if (user.getStatus() == UserStatus.SUSPENDED) {
            throw new UsernameNotFoundException("Account is suspended");
        }

        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toList());

        return org.springframework.security.core.userdetails.User
            .withUsername(user.getEmail())
            .password(user.getPassword())
            .authorities(authorities)
            .accountLocked(user.isLocked())
            .build();
    }

    // ─── Profile Operations ──────────────────────────────────────────────────

    public UserProfile getUserProfile(String email) {
        String tenantId = TenantContext.getCurrentTenant();
        User user = userRepository.findByEmailAndTenantId(email, tenantId)
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return mapToProfile(user);
    }

    @Transactional
    public UserProfile updateUserProfile(String email, Map<String, Object> updates) {
        String tenantId = TenantContext.getCurrentTenant();
        User user = userRepository.findByEmailAndTenantId(email, tenantId)
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (updates.containsKey("firstName")) user.setFirstName((String) updates.get("firstName"));
        if (updates.containsKey("lastName"))  user.setLastName((String) updates.get("lastName"));
        if (updates.containsKey("phone"))     user.setPhone((String) updates.get("phone"));

        return mapToProfile(userRepository.save(user));
    }

    // ─── Admin Operations ────────────────────────────────────────────────────

    public Page<UserProfile> listUsers(String role, String status, Pageable pageable) {
        String tenantId = TenantContext.getCurrentTenant();
        return userRepository.findByTenantId(tenantId, pageable)
            .map(this::mapToProfile);
    }

    @Transactional
    public UserProfile updateUserRoles(String userId, Map<String, Object> body) {
        String tenantId = TenantContext.getCurrentTenant();
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));

        @SuppressWarnings("unchecked")
        List<String> roleNames = (List<String>) body.get("roles");
        Set<Role> roles = roleNames.stream()
            .map(name -> roleRepository.findByName(name)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + name)))
            .collect(Collectors.toSet());

        user.setRoles(roles);
        return mapToProfile(userRepository.save(user));
    }

    @Transactional
    public void deleteUser(String userId) {
        String tenantId = TenantContext.getCurrentTenant();
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setStatus(UserStatus.DELETED);
        userRepository.save(user);
    }

    @Transactional
    public void unlockUser(String userId) {
        String tenantId = TenantContext.getCurrentTenant();
        User user = userRepository.findByIdAndTenantId(userId, tenantId)
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setLockedUntil(null);
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
        log.info("Account unlocked for user: {}", userId);
    }

    // ─── Mapping ─────────────────────────────────────────────────────────────

    private UserProfile mapToProfile(User user) {
        Set<String> roleNames = user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.toSet());

        return UserProfile.builder()
            .id(user.getId())
            .email(user.getEmail())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .tenantId(user.getTenantId())
            .roles(roleNames)
            .status(user.getStatus().name())
            .twoFactorEnabled(user.isTwoFactorEnabled())
            .lastLoginAt(user.getLastLoginAt())
            .build();
    }
}
