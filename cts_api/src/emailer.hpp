// ==============================================================================
// CTS ZERO TRUST ENGINE - EMAIL DISPATCH SYSTEM (HEADER)
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
#pragma once
#include <string>

namespace EmailClient {
    bool send_smtp_email(const std::string& to_email, 
                         const std::string& subject, 
                         const std::string& html_body, 
                         const std::string& attachment_name = "", 
                         const std::string& attachment_data = "");

    bool send_welcome_email(const std::string& to_email, 
                            const std::string& username, 
                            const std::string& full_name, 
                            const std::string& temp_password, 
                            const std::string& encrypted_wg_profile = "");

    bool send_password_reset(const std::string& to_email, 
                             const std::string& full_name, 
                             const std::string& reset_token);
}