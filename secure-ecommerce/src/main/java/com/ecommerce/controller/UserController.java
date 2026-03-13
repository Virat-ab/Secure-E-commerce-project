package com.ecommerce.controller;

import com.ecommerce.model.dto.UserProfile;
import com.ecommerce.security.audit.SecurityAudit;
import com.ecommerce.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * GET /api/users/me
     * Returns the authenticated user's profile.
     */
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserProfile> getCurrentUser(
            @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.getUserProfile(userDetails.getUsername()));
    }

    /**
     * PUT /api/users/me
     * Update the authenticated user's profile details.
     */
    @PutMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @SecurityAudit(action = "PROFILE_UPDATE")
    public ResponseEntity<UserProfile> updateCurrentUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody Map<String, Object> updates) {
        return ResponseEntity.ok(
            userService.updateUserProfile(userDetails.getUsername(), updates));
    }

    /**
     * GET /api/users
     * List all users within the current tenant. Admin only.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserProfile>> listUsers(
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String status,
            Pageable pageable) {
        return ResponseEntity.ok(userService.listUsers(role, status, pageable));
    }

    /**
     * PUT /api/users/{id}/roles
     * Assign roles to a user. Admin only.
     */
    @PutMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityAudit(action = "ROLE_UPDATE")
    public ResponseEntity<UserProfile> updateUserRoles(
            @PathVariable String id,
            @RequestBody Map<String, Object> body) {
        return ResponseEntity.ok(userService.updateUserRoles(id, body));
    }

    /**
     * DELETE /api/users/{id}
     * Soft-delete a user. Admin only.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityAudit(action = "USER_DELETE")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * POST /api/users/{id}/unlock
     * Unlock a locked account. Admin only.
     */
    @PostMapping("/{id}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityAudit(action = "ACCOUNT_UNLOCK")
    public ResponseEntity<Map<String, String>> unlockUser(@PathVariable String id) {
        userService.unlockUser(id);
        return ResponseEntity.ok(Map.of("message", "User account unlocked"));
    }
}
