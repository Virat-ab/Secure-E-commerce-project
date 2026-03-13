package com.ecommerce.repository;

import com.ecommerce.model.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByEmailAndTenantId(String email, String tenantId);

    Optional<User> findByIdAndTenantId(String id, String tenantId);

    boolean existsByEmailAndTenantId(String email, String tenantId);

    Page<User> findByTenantId(String tenantId, Pageable pageable);
}
