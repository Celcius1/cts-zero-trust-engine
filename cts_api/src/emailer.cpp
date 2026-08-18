// ==============================================================================
// CTS ZERO TRUST ENGINE - EMAIL DISPATCH SYSTEM (IMPLEMENTATION)
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
#include "emailer.hpp"
#include "zero_trust_engine.hpp"
#include <Poco/Net/MailMessage.h>
#include <Poco/Net/MailRecipient.h>
#include <Poco/Net/SMTPClientSession.h>
#include <Poco/Net/SecureSMTPClientSession.h>
#include <Poco/Net/StringPartSource.h>
#include <Poco/Net/SSLManager.h>
#include <Poco/Net/AcceptCertificateHandler.h>
#include <Poco/Net/Context.h>
#include <Poco/Exception.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <mutex>

namespace fs = std::filesystem;

namespace EmailClient {

    std::mutex log_mutex;

    void log_event(const std::string& message) {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S");
        
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cout << "[" << ss.str() << "] [CTS-EMAIL] " << message << std::endl;
    }

    std::string read_file_to_string(const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) return "";
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    void replace_all_tags(std::string& str, const std::string& from, const std::string& to) {
        size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != std::string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }
    }

    bool send_smtp_email(const std::string& to_email, const std::string& subject, const std::string& html_body, const std::string& attachment_name, const std::string& attachment_data) {
        try {
            std::string smtp_host = get_env("SMTP_HOST", "mail.osl.net.au");
            int smtp_port = std::stoi(get_env("SMTP_PORT", "587"));
            std::string smtp_user = get_env("SMTP_USER", "noreply@osl.net.au");
            std::string smtp_pass = get_env("SMTP_PASSWORD", "Pr@toss224581");
            std::string from_email = get_env("SMTP_USER", "noreply@osl.net.au");

            Poco::Net::MailMessage message;
            message.setSender(from_email);
            message.addRecipient(Poco::Net::MailRecipient(Poco::Net::MailRecipient::PRIMARY_RECIPIENT, to_email));
            message.setSubject(subject);

            // FIX: Explicitly declaring Inline disposition and 8-bit encoding for the HTML body
            message.addPart("", new Poco::Net::StringPartSource(html_body, "text/html"), Poco::Net::MailMessage::CONTENT_INLINE, Poco::Net::MailMessage::ENCODING_8BIT);

            if (!attachment_name.empty() && !attachment_data.empty()) {
                // FIX: Explicitly declaring Attachment disposition and Base64 encoding for the file
                message.addPart(attachment_name, new Poco::Net::StringPartSource(attachment_data, "application/octet-stream"), Poco::Net::MailMessage::CONTENT_ATTACHMENT, Poco::Net::MailMessage::ENCODING_BASE64);
            }

            Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> ptrCert = new Poco::Net::AcceptCertificateHandler(false);
            Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(Poco::Net::Context::CLIENT_USE, "", "", "", Poco::Net::Context::VERIFY_NONE, 9, false, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
            Poco::Net::SSLManager::instance().initializeClient(0, ptrCert, ptrContext);

            Poco::Net::SecureSMTPClientSession session(smtp_host, smtp_port);
            session.login();
            session.startTLS(ptrContext);
            session.login(Poco::Net::SMTPClientSession::AUTH_LOGIN, smtp_user, smtp_pass);
            session.sendMessage(message);
            session.close();

            log_event("Email successfully delivered to: " + to_email);
            return true;

        } catch (Poco::Exception& exc) {
            log_event("Failed to send email to " + to_email + ". Error: " + exc.displayText());
            return false;
        } catch (std::exception& exc) {
            log_event("Standard exception during email delivery: " + std::string(exc.what()));
            return false;
        }
    }

    bool send_welcome_email(const std::string& to_email, const std::string& username, const std::string& full_name, const std::string& temp_password, const std::string& encrypted_wg_profile) {
        std::string template_path = "/data/config/emails/welcome_template.html";
        std::string html = read_file_to_string(template_path);
        
        if (html.empty()) {
            log_event("ERROR: welcome_template.html missing or empty. Aborting delivery to " + to_email);
            return false; 
        }

        replace_all_tags(html, "{USERNAME}", username);
        replace_all_tags(html, "{FULL_NAME}", full_name);
        replace_all_tags(html, "{TEMP_PASSWORD}", temp_password);

        std::string config_filename = username + "_cts_secure_profile.cai";
        return send_smtp_email(to_email, "Welcome to CTS Zero Trust Engine - Account Provisioned", html, config_filename, encrypted_wg_profile);
    }

    bool send_password_reset(const std::string& to_email, const std::string& full_name, const std::string& reset_token) {
        std::string template_path = "/data/config/emails/reset_template.html";
        std::string html = read_file_to_string(template_path);
        
        if (html.empty()) {
            log_event("ERROR: reset_template.html missing or empty. Aborting Reset Email to " + to_email);
            return false;
        }

        replace_all_tags(html, "{FULL_NAME}", full_name);
        replace_all_tags(html, "{RESET_TOKEN}", reset_token);

        return send_smtp_email(to_email, "CTS Security Architecture - Security Reset Token Request", html);
    }
}