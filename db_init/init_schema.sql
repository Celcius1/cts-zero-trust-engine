-- ==============================================================================
-- CEL-TECH-SERV ZERO TRUST ENGINE - CORE SCHEMA
-- Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; 

-- ==============================================================================
-- TABLE: users
-- CTS ZERO TRUST IDENTITY LEDGER
-- ==============================================================================
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) NOT NULL,
    full_name VARCHAR(150),
    email_address VARCHAR(255) UNIQUE,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    profile_photo_path TEXT,
    reset_token VARCHAR(10),
    reset_token_expiry TIMESTAMP WITH TIME ZONE,
    must_change_password BOOLEAN DEFAULT TRUE,
    
    -- WireGuard Cryptographic Tracking
    provisioning_token VARCHAR(64) UNIQUE,
    provisioning_expiry TIMESTAMP WITH TIME ZONE,
    temp_vpn_public_key VARCHAR(50),
    temp_vpn_ip_address VARCHAR(20) UNIQUE,
    vpn_public_key VARCHAR(50),
    vpn_ip_address VARCHAR(20) UNIQUE
);

-- ==============================================================================
-- SYSTEM SETTINGS
-- ==============================================================================
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO system_settings (key, value) VALUES ('engine_version', '1.0.0') ON CONFLICT DO NOTHING;