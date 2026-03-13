-- V1__init.sql
-- Initial schema for Secure E-commerce Platform

-- Tenants table (shared schema)
CREATE TABLE IF NOT EXISTS tenants (
    id          VARCHAR(36) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    subdomain   VARCHAR(100) UNIQUE NOT NULL,
    status      VARCHAR(50)  NOT NULL DEFAULT 'ACTIVE',
    plan        VARCHAR(50)  NOT NULL DEFAULT 'STANDARD',
    admin_email VARCHAR(255),
    max_users   INT          NOT NULL DEFAULT 100,
    rate_limit_tier        VARCHAR(20) DEFAULT 'MEDIUM',
    two_factor_required    BOOLEAN     DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id   BIGSERIAL   PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

INSERT INTO roles (name) VALUES
    ('ROLE_ADMIN'),
    ('ROLE_VENDOR'),
    ('ROLE_CUSTOMER')
ON CONFLICT (name) DO NOTHING;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id                      VARCHAR(36)  PRIMARY KEY,
    email                   VARCHAR(255) NOT NULL,
    password                VARCHAR(255) NOT NULL,
    first_name              VARCHAR(100),
    last_name               VARCHAR(100),
    phone                   VARCHAR(20),
    tenant_id               VARCHAR(36)  NOT NULL,
    status                  VARCHAR(50)  NOT NULL DEFAULT 'ACTIVE',
    provider                VARCHAR(50)  NOT NULL DEFAULT 'LOCAL',
    provider_id             VARCHAR(255),
    failed_login_attempts   INT          NOT NULL DEFAULT 0,
    locked_until            TIMESTAMP,
    last_login_at           TIMESTAMP,
    email_verified_at       TIMESTAMP,
    two_factor_enabled      BOOLEAN      NOT NULL DEFAULT FALSE,
    two_factor_secret       VARCHAR(255),
    created_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (email, tenant_id)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email  ON users(email);

-- User roles mapping
CREATE TABLE IF NOT EXISTS user_roles (
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT      NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Security audit events (shared schema for compliance)
CREATE TABLE IF NOT EXISTS security_events (
    id            BIGSERIAL    PRIMARY KEY,
    action        VARCHAR(100) NOT NULL,
    outcome       VARCHAR(20)  NOT NULL,
    username      VARCHAR(255),
    tenant_id     VARCHAR(36),
    ip_address    VARCHAR(45),
    error_message TEXT,
    timestamp     TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_event_username  ON security_events(username);
CREATE INDEX idx_event_tenant    ON security_events(tenant_id);
CREATE INDEX idx_event_timestamp ON security_events(timestamp);
CREATE INDEX idx_event_action    ON security_events(action);

-- Seed default admin tenant
INSERT INTO tenants (id, name, subdomain, status, plan, admin_email)
VALUES ('00000000-0000-0000-0000-000000000001', 'Platform Admin', 'admin', 'ACTIVE', 'ENTERPRISE', 'admin@platform.com')
ON CONFLICT DO NOTHING;
