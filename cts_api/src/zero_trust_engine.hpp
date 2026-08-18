// ==============================================================================
// CTS ZERO TRUST ENGINE - CORE CRYPTOGRAPHY (HEADER)
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
#pragma once
#include <string>

struct MobileSubToken {
    std::string public_key_b64;
    std::string assigned_ip;  
    std::string encrypted_qr_payload_b64;
};

MobileSubToken generate_mobile_sub_token(const std::string& username, const std::string& sub_token_password, bool is_jail_profile = true);
std::string get_env(const std::string& var, const std::string& default_value);