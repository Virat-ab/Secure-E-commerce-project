package com.ecommerce.model.enums;

public enum Permission {
    // User permissions
    READ_USERS,
    WRITE_USERS,
    DELETE_USERS,

    // Product permissions
    READ_PRODUCTS,
    WRITE_PRODUCTS,
    DELETE_PRODUCTS,

    // Order permissions
    READ_ORDERS,
    WRITE_ORDERS,
    UPDATE_ORDER_STATUS,

    // Tenant permissions
    READ_TENANTS,
    WRITE_TENANTS,
    MANAGE_TENANTS,

    // Audit permissions
    READ_AUDIT_LOGS,

    // Admin permissions
    MANAGE_ROLES,
    SYSTEM_CONFIG
}
