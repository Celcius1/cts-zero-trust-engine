// ==============================================================================
// CTS ZERO TRUST ENGINE - MAIN API GATEWAY
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
// Description: The primary Layer 7 REST API Gateway driving the Zero Trust
//              Architecture. Handles initial out-of-box provisioning, WireGuard 
//              key negotiations, Identity & Access Management (IAM), and serves 
//              dynamic Server-Driven UI (SDUI) configurations to client apps.
// ==============================================================================

#include <iostream>
#include <fstream>
#include <filesystem>
#include <random>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <sodium.h>
#include <pqxx/pqxx>
#include "httplib.h"
#include "zero_trust_engine.hpp"
#include "db_engine.hpp"
#include "emailer.hpp"
#include "nlohmann/json.hpp"

// ------------------------------------------------------------------------------
// GLOBAL THREAD-SAFE STATE VARIABLES
// ------------------------------------------------------------------------------
// Out-Of-Box Experience (OOBE) provisioning state
std::string current_builders_pin = "";
std::string current_builder_wg_block = ""; 
std::mutex bootstrap_mutex;

// Security trap flag: When false, permanently locks the unauthenticated provisioning routes
std::atomic<bool> open_web_interface_active{true};

// Global state tracker: Increments on any IAM/Database change to force connected C# clients to refresh
std::atomic<uint64_t> global_state_version{1};

// ==============================================================================
// CTS ZERO TRUST ENGINE - SESSION MANAGEMENT
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
// INSTRUCTIONS: Replace the existing active_sessions map at the top of main.cpp
// with this expanded struct and map to support rolling timeouts.
// ==============================================================================

struct SessionData {
    std::string username;
    std::string role;
    std::chrono::system_clock::time_point expiry;
};

// Global thread-safe session vault
std::unordered_map<std::string, SessionData> active_sessions;
std::mutex session_mutex;

// ==============================================================================
// CEL-TECH-SERV PTY LTD: LAYER 7 REVERSE PROXY CONFIGURATION
// Holds agnostic routing definitions loaded from disk.
// ==============================================================================
struct RouteTarget {
    std::string host;
    int port;
    std::vector<std::string> managed_apps;
};
std::unordered_map<std::string, RouteTarget> gateway_routes;

void load_gateway_routes() {
    try {
        std::ifstream file("/data/config/gateway_routes.json");
        if (file.is_open()) {
            nlohmann::json config;
            file >> config;
            for (const auto& route : config["routes"]) {
                std::string prefix = route["prefix"];
                std::string host = route["upstream_host"];
                int port = route["upstream_port"];
                
                std::vector<std::string> apps;
                if (route.contains("managed_apps")) {
                    for (const auto& app : route["managed_apps"]) apps.push_back(app);
                }
                
                gateway_routes[prefix] = {host, port, apps};
                std::cout << "[CTS-API] Agnostic Route Locked: " << prefix << " -> " << host << ":" << port << "\n";
            }
        }
    } catch (...) {
        std::cerr << "[CTS-API] WARNING: gateway_routes.json missing or malformed. Traffic Cop inactive.\n";
    }
}

// Defines the idle timeout duration for operators (e.g., 15 minutes)
const int SESSION_TIMEOUT_MINUTES = 15;

// Helper function to generate a cryptographically secure bearer token
std::string generate_secure_bearer_token() {
    unsigned char token_bin[32];
    randombytes_buf(token_bin, sizeof(token_bin));
    char token_hex[65];
    sodium_bin2hex(token_hex, sizeof(token_hex), token_bin, sizeof(token_bin));
    return std::string(token_hex);
}

// ------------------------------------------------------------------------------
// SECURITY: MAGIC BYTE FILE VALIDATION
// ------------------------------------------------------------------------------
bool is_valid_image_payload(const std::string& data, std::string& out_extension) {
    if (data.size() < 8) return false;

    // Check for PNG Magic Bytes: 89 50 4E 47 0D 0A 1A 0A
    const unsigned char png_magic[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    bool is_png = true;
    for (int i = 0; i < 8; ++i) {
        if (static_cast<unsigned char>(data[i]) != png_magic[i]) is_png = false;
    }
    
    if (is_png) {
        out_extension = ".png";
        return true;
    }

    // Check for JPEG Magic Bytes: FF D8 FF
    if (static_cast<unsigned char>(data[0]) == 0xFF && 
        static_cast<unsigned char>(data[1]) == 0xD8 && 
        static_cast<unsigned char>(data[2]) == 0xFF) {
        out_extension = ".jpg";
        return true;
    }

    return false;
}

// ------------------------------------------------------------------------------
// CRYPTOGRAPHIC HELPER: SESSION TOKEN GENERATION
// ------------------------------------------------------------------------------
std::string generate_session_token() {
    unsigned char token_bin[32];
    randombytes_buf(token_bin, sizeof(token_bin));
    
    char token_b64[100];
    sodium_bin2base64(token_b64, sizeof(token_b64), token_bin, sizeof(token_bin), sodium_base64_VARIANT_ORIGINAL);
    
    return std::string(token_b64);
}

// ==============================================================================
// MAIN ENTRY POINT
// ==============================================================================
int main() {
    // 1. Initialize libsodium for all password hashing and key generation
    if (sodium_init() < 0) {
        std::cerr << "[CTS-API] FATAL: Failed to initialise libsodium\n";
        return 1;
    }

    // 2. Load the dynamic Traffic Cop routes
    load_gateway_routes();

    httplib::Server svr;

    // ------------------------------------------------------------------------------
    // GLOBAL MIDDLEWARE: LOGGING & CORS
    // ------------------------------------------------------------------------------
    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::cout << "[CTS-API] HTTP " << req.method << " " << req.path 
                  << " from " << req.remote_addr << " - Status: " << res.status << "\n";
        std::cout.flush();
    });

    // ==============================================================================
    // MIDDLEWARE: ROLLING BEARER TOKEN VALIDATION & TRAFFIC COP
    // Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
    // ==============================================================================
    svr.set_pre_routing_handler([](const httplib::Request &req, httplib::Response &res) {
        // 1. Allow unauthenticated paths (Login, Bootstrapping, Web UI, Hooks)
        if (req.path == "/api/v1/auth/login" || 
            req.path == "/claim" || 
            req.path == "/user-claim" ||
            req.path == "/health" ||
            req.path.find("/api/v1/bootstrap/") == 0 ||
            req.path.find("/download/") == 0 ||
            req.path == "/") {
            return httplib::Server::HandlerResponse::Unhandled;
        }

        // 2. Extract Bearer Token
        std::string auth_header = req.has_header("Authorization") ? req.get_header_value("Authorization") : "";
        if (auth_header.find("Bearer ") != 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Missing or invalid bearer token.\"}", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        
        std::string token = auth_header.substr(7); // Strip "Bearer "

        // 3. Validate and Roll the Token
        std::lock_guard<std::mutex> lock(session_mutex);
        auto it = active_sessions.find(token);
        
        if (it == active_sessions.end()) {
            res.status = 401;
            res.set_content("{\"error\":\"Session invalid or expired.\"}", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }

        auto now = std::chrono::system_clock::now();
        if (now > it->second.expiry) {
            active_sessions.erase(it); // Purge expired session
            res.status = 401;
            res.set_content("{\"error\":\"Session timed out due to inactivity.\"}", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }

        // 4. THE ROLLING MECHANISM
        if (req.path != "/api/v1/state") {
            it->second.expiry = now + std::chrono::minutes(SESSION_TIMEOUT_MINUTES);
        }

        // ==============================================================================
        // CEL-TECH-SERV PTY LTD: THE TRAFFIC COP (LAYER 7 PROXY)
        // Dynamically routes requests to external isolated Docker stacks (e.g., OSL)
        // only AFTER cryptographic authentication has passed.
        // ==============================================================================
        for (const auto& [prefix, target] : gateway_routes) {
            if (req.path.find(prefix) == 0) {
                httplib::Client cli(target.host, target.port);
                cli.set_connection_timeout(5, 0); 
                cli.set_read_timeout(10, 0);
                
                httplib::Headers proxy_headers = {
                    {"Authorization", "Bearer " + token},
                    {"Content-Type", req.has_header("Content-Type") ? req.get_header_value("Content-Type") : "application/json"}
                };

                httplib::Result proxy_res;
                
                if (req.method == "GET") {
                    proxy_res = cli.Get(req.path, proxy_headers);
                } else if (req.method == "POST") {
                    proxy_res = cli.Post(req.path, proxy_headers, req.body, req.get_header_value("Content-Type"));
                } else if (req.method == "PUT") {
                    proxy_res = cli.Put(req.path, proxy_headers, req.body, req.get_header_value("Content-Type"));
                } else if (req.method == "DELETE") {
                    proxy_res = cli.Delete(req.path, proxy_headers, req.body, req.get_header_value("Content-Type"));
                }

                if (proxy_res) {
                    res.status = proxy_res->status;
                    res.set_content(proxy_res->body, proxy_res->get_header_value("Content-Type"));
                } else {
                    res.status = 502;
                    res.set_content("{\"error\":\"Bad Gateway. Target Sovereign stack is unreachable.\"}", "application/json");
                }
                
                return httplib::Server::HandlerResponse::Handled;
            }
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    // ==============================================================================
    // MIDDLEWARE: ROLLING BEARER TOKEN VALIDATION
    // Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
    // ==============================================================================
    // INSTRUCTIONS: Paste this directly underneath your existing CORS 
    // set_pre_routing_handler in main.cpp.
    // ==============================================================================
    
    svr.set_pre_routing_handler([](const httplib::Request &req, httplib::Response &res) {
        // 1. Allow unauthenticated paths (Login, Bootstrapping, Web UI, Hooks)
        if (req.path == "/api/v1/auth/login" || 
            req.path == "/claim" || 
            req.path == "/user-claim" ||
            req.path == "/health" ||
            req.path.find("/api/v1/bootstrap/") == 0 ||
            req.path.find("/download/") == 0 ||
            req.path == "/") {
            return httplib::Server::HandlerResponse::Unhandled;
        }

        // 2. Extract Bearer Token
        std::string auth_header = req.has_header("Authorization") ? req.get_header_value("Authorization") : "";
        if (auth_header.find("Bearer ") != 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Missing or invalid bearer token.\"}", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        
        std::string token = auth_header.substr(7); // Strip "Bearer "

        // 3. Validate and Roll the Token
        std::lock_guard<std::mutex> lock(session_mutex);
        auto it = active_sessions.find(token);
        
        if (it == active_sessions.end()) {
            res.status = 401;
            res.set_content("{\"error\":\"Session invalid or expired.\"}", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }

        auto now = std::chrono::system_clock::now();
        if (now > it->second.expiry) {
            active_sessions.erase(it); // Purge expired session
            res.status = 401;
            res.set_content("{\"error\":\"Session timed out due to inactivity.\"}", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }

        // 4. THE ROLLING MECHANISM
        // We only extend the expiry time if the request is an active user action.
        // Background polls (like the Avalonia state sync) do NOT keep the session alive.
        if (req.path != "/api/v1/state") {
            it->second.expiry = now + std::chrono::minutes(SESSION_TIMEOUT_MINUTES);
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    // ------------------------------------------------------------------------------
    // HEALTH & STATE SYNCHRONISATION
    // ------------------------------------------------------------------------------
    
    // Polled silently by the Avalonia client to detect backend database updates
    svr.Get("/api/v1/state", [](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json response;
        response["state_version"] = global_state_version.load();
        res.set_content(response.dump(), "application/json");
    });

    // Standard heartbeat endpoint
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json response;
        response["status"] = "online";
        response["service"] = "CTS Zero Trust Engine";
        res.set_content(response.dump(), "application/json");
    });

    // ==============================================================================
    // PHASE 1: FACTORY HANDOVER ENDPOINT (INITIAL SYSTEM BOOTSTRAP)
    // Consumes the one-time Web PIN to create the root System Administrator.
    // ==============================================================================
    svr.Post("/claim", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "[CTS-API] FACTORY HANDOVER ATTEMPT - RAW BODY: " << req.body << "\n";
        std::cout.flush();

        // Security check: Ensure the web gateway is actively accepting claims
        if (!open_web_interface_active) {
            res.status = 403;
            res.set_content("{\"error\":\"Bootstrap phase locked.\"}", "application/json");
            return;
        }

        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string provided_pin = json_body.value("pin", "");
            std::string username = json_body.value("username", "");
            std::string password = json_body.value("pass", "");

            if (provided_pin.empty() || username.empty() || password.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"Please fill out all fields.\"}", "application/json");
                return;
            }

            // ZERO-TRUST SECURITY TRAP: If a master admin already exists in the DB, 
            // permanently disable this unauthenticated route to prevent hijacking.
            extern bool is_master_admin_present();
            if (is_master_admin_present()) {
                open_web_interface_active = false;
                current_builders_pin = "";
                
                std::cout << "\n[CTS SECURITY] ⚠️ TRAP SPRUNG! ⚠️\n"
                          << "[CTS SECURITY] Unauthorized attempt to access the Factory Builder Endpoint.\n"
                          << "[CTS SECURITY] Perimeter locked down immediately.\n\n";
                std::cout.flush();

                res.status = 403;
                res.set_content("{\"error\":\"Security Trap: Factory Bootstrap permanently disabled.\"}", "application/json");
                return;
            }

            // Validate the console-generated PIN
            std::lock_guard<std::mutex> lock(bootstrap_mutex);
            if (provided_pin != current_builders_pin || current_builders_pin.empty()) {
                res.status = 401;
                res.set_content("{\"error\":\"Invalid PIN.\"}", "application/json");
                return;
            }

            // Generate a temporary "Jail" WireGuard configuration payload (.cai)
            MobileSubToken token = generate_mobile_sub_token(username, password, true);

            // Hash the Master Password using Libsodium Argon2id
            char hashed_pw[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(hashed_pw, password.c_str(), password.length(), 
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE, 
                                  crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
                throw std::runtime_error("Out of memory hashing password");
            }

            // Inject the Root Administrator into PostgreSQL
            extern std::string get_db_string(); 
            pqxx::connection conn(get_db_string());
            pqxx::work W(conn);
            W.exec_params(
                "INSERT INTO users (username, full_name, password_hash, role, temp_vpn_public_key, temp_vpn_ip_address, must_change_password) "
                "VALUES ($1, 'System Administrator', $2, 'Administrator', $3, $4, TRUE)",
                username, std::string(hashed_pw), token.public_key_b64, token.assigned_ip
            );
            W.commit();

            // Append the temporary jail profile to wg0.conf
            std::string wg_conf_path = "/data/vpn_config/wg_confs/wg0.conf";
            current_builder_wg_block = "\n# [CTS Builder Temporary Access]\n"
                                       "[Peer]\n"
                                       "PublicKey = " + token.public_key_b64 + "\n"
                                       "AllowedIPs = " + token.assigned_ip + "/32\n";

            std::ofstream wg_file(wg_conf_path, std::ios::app);
            if (wg_file.is_open()) {
                wg_file << current_builder_wg_block;
                wg_file.close();
            }

            // Trigger the Gentoo/OpenRC WireGuard background daemon to reload the config
            std::ofstream flag_file("/data/config/reload.flag");
            if (flag_file.is_open()) {
                flag_file << "reload";
                flag_file.close();
            }

            // Overwrite PIN with the user password to prepare for Phase 2 Client Handover
            current_builders_pin = password;
            open_web_interface_active = false;
            
            global_state_version++; // Notify system of state change

            nlohmann::json response;
            response["status"] = "success";
            response["cai_payload"] = token.encrypted_qr_payload_b64;
            res.set_content(response.dump(), "application/json");

            std::cout << "[CTS-API] Builder's Key issued & Master Admin configured. Gateway Locked.\n";
            std::cout.flush();

        } catch (const std::exception& e) {
            std::cout << "[CTS-API] CLAIM ERROR: " << e.what() << "\n";
            res.status = 400;
            res.set_content("{\"error\":\"Failed to process handover.\"}", "application/json");
        }
    });

    // ==============================================================================
    // PHASE 2: PERMANENT DEVICE HANDOVER ENDPOINT (C# DESKTOP CLIENT)
    // Consumes the temporary .cai payload, validates identity, and issues a 
    // permanent, un-jailed WireGuard IP for daily operator use.
    // ==============================================================================
    svr.Post("/api/v1/bootstrap/device-handover", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "[CTS-API] PERMANENT HANDOVER ATTEMPT - RAW BODY: " << req.body << "\n";
        std::cout.flush();

        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string provided_pin = json_body.value("pin", ""); 
            std::string client_pubkey = json_body.value("public_key", "");
            std::string machine_name = json_body.value("machine_name", "Unknown_Device");

            if (provided_pin.empty() || client_pubkey.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"Missing payload data.\"}", "application/json");
                return;
            }

            // Extract users currently waiting in the temporary Jail subnet
            extern std::string get_db_string();
            pqxx::connection conn(get_db_string());
            pqxx::work W(conn);
            
            pqxx::result db_res = W.exec("SELECT user_id, username, password_hash, temp_vpn_public_key, temp_vpn_ip_address FROM users WHERE temp_vpn_ip_address IS NOT NULL");
            
            std::string matched_user_id = "";
            std::string matched_username = "";
            std::string temp_pub = "";
            std::string temp_ip = "";

            // Verify the client-provided password against the stored hashes
            for (auto row : db_res) {
                std::string stored_hash = row["password_hash"].c_str();
                if (crypto_pwhash_str_verify(stored_hash.c_str(), provided_pin.c_str(), provided_pin.length()) == 0) {
                    matched_user_id = row["user_id"].c_str();
                    matched_username = row["username"].c_str();
                    temp_pub = row["temp_vpn_public_key"].c_str();
                    temp_ip = row["temp_vpn_ip_address"].c_str();
                    break;
                }
            }

            if (matched_user_id.empty()) {
                std::cout << "[CTS-API] HANDOVER REJECTED: Invalid Password or no active jail profile found.\n";
                res.status = 401;
                res.set_content("{\"error\":\"Invalid credentials.\"}", "application/json");
                return;
            }

            // Assign a permanent IP inside the highly trusted subnet
            std::string subnet_prefix = get_env("VPN_TRUSTED_SUBNET_PREFIX", "10.13.13.");
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dist(10, 250);
            std::string permanent_ip = subnet_prefix + std::to_string(dist(gen));

            // Surgically locate and destroy the temporary jail block in wg0.conf
            std::string wg_conf_path = "/data/vpn_config/wg_confs/wg0.conf";
            std::ifstream in(wg_conf_path);
            std::stringstream buffer;
            buffer << in.rdbuf();
            std::string file_contents = buffer.str();
            in.close();

            std::string block_to_remove = "\n# [CTS Builder Temporary Access]\n"
                                          "[Peer]\n"
                                          "PublicKey = " + temp_pub + "\n"
                                          "AllowedIPs = " + temp_ip + "/32\n";
            
            size_t pos = file_contents.find(block_to_remove);
            if (pos != std::string::npos) {
                file_contents.erase(pos, block_to_remove.length());
                std::cout << "[CTS-API] Surgically removed temporary jail profile from wg0.conf.\n";
            }

            // Append the new permanent routing block
            std::string permanent_block = "\n# [CTS Permanent Access] " + matched_username + " (" + machine_name + ")\n"
                                          "[Peer]\n"
                                          "PublicKey = " + client_pubkey + "\n"
                                          "AllowedIPs = " + permanent_ip + "/32\n";
            file_contents += permanent_block;

            std::ofstream out(wg_conf_path, std::ios::trunc);
            if (out.is_open()) {
                out << file_contents;
                out.close();
            }

            // Unset temp columns in PostgreSQL and lock in permanent metrics
            W.exec_params("UPDATE users SET temp_vpn_public_key = NULL, temp_vpn_ip_address = NULL, vpn_public_key = $1, vpn_ip_address = $2 WHERE user_id = $3",
                          client_pubkey, permanent_ip, matched_user_id);
            W.commit();

            // Notify Gentoo to execute `wg syncconf`
            std::ofstream flag_file("/data/config/reload.flag");
            if (flag_file.is_open()) { 
                flag_file << "reload"; 
                flag_file.close(); 
            }

            open_web_interface_active = false; 
            global_state_version++; // Notify system of ledger status change

            nlohmann::json response;
            response["AssignedIP"] = permanent_ip;
            response["ServerPublicKey"] = get_env("VPN_SERVER_PUBKEY", "PLACEHOLDER");
            response["Endpoint"] = get_env("VPN_EXTERNAL_IP", "144.6.20.158") + ":51820";

            res.set_content(response.dump(), "application/json");
            std::cout << "[CTS-API] Handover successful for " << machine_name << ". Permanent IP: " << permanent_ip << "\n";

        } catch (const std::exception& e) {
            std::cout << "[CTS-API] HANDOVER ERROR: " << e.what() << "\n";
            res.status = 400;
            res.set_content("{\"error\":\"Bad request.\"}", "application/json");
        }
    });

    // ==============================================================================
    // SERVER-DRIVEN UI (SDUI) WORKSPACE GENERATOR
    // Parses individual JSON modules from disk and aggregates them into a payload.
    // ==============================================================================
    svr.Get("/api/v1/sdui/dashboard", [](const httplib::Request& req, httplib::Response& res) {
        if (req.remote_addr.find("10.13.13.") != 0 && req.remote_addr.find("172.22.") != 0) {
            res.status = 403;
            res.set_content("{\"error\":\"Untrusted Network. SDUI Access Denied.\"}", "application/json");
            return;
        }

        std::string core_config_path = "/data/config/sdui_core.json";
        std::ifstream file(core_config_path);
        
        if (!file.is_open()) {
            res.status = 500;
            res.set_content("{\"error\":\"Core SDUI configuration missing on server.\"}", "application/json");
            return;
        }

        nlohmann::json sdui_payload;
        try {
            file >> sdui_payload;
        } catch (...) {
            res.status = 500;
            res.set_content("{\"error\":\"Core SDUI JSON is malformed.\"}", "application/json");
            return;
        }

        if (!sdui_payload.contains("apps")) {
            sdui_payload["apps"] = nlohmann::json::array();
        }

        // Loop through all modular app plugins and aggregate them
        std::string apps_dir = "/data/config/sdui_apps.d/";
        if (std::filesystem::exists(apps_dir)) {
            for (const auto& entry : std::filesystem::directory_iterator(apps_dir)) {
                if (entry.path().extension() == ".json") {
                    std::ifstream app_file(entry.path());
                    if (app_file.is_open()) {
                        try {
                            nlohmann::json app_json;
                            app_file >> app_json;
                            sdui_payload["apps"].push_back(app_json); 
                        } catch (...) {
                            std::cerr << "[CTS-API] WARNING: Failed to parse modular SDUI file: " << entry.path() << "\n";
                        }
                    }
                }
            }
        }

        res.set_content(sdui_payload.dump(), "application/json");
    });

    // ==============================================================================
    // CORE AUTHENTICATION (SSO LOGIN) - UPDATED FOR ROLLING TOKENS
    // ==============================================================================
    // INSTRUCTIONS: Replace your existing /api/v1/auth/login block with this one.
    // ==============================================================================
    
    svr.Post("/api/v1/auth/login", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string user = json_body.value("username", "");
            std::string pass = json_body.value("password", "");
            std::string user_role = "";
            bool must_change = false;

            if (authenticate_user(user, pass, user_role, must_change)) {
                
                // Generate secure hardware-backed token
                std::string secure_token = generate_secure_bearer_token();
                
                // Register the session in memory with an expiry time
                {
                    std::lock_guard<std::mutex> lock(session_mutex);
                    active_sessions[secure_token] = SessionData{
                        user, 
                        user_role, 
                        std::chrono::system_clock::now() + std::chrono::minutes(SESSION_TIMEOUT_MINUTES)
                    };
                }
                
                nlohmann::json response;
                response["token"] = secure_token;
                response["user"] = user;
                response["role"] = user_role; 
                response["must_change_password"] = must_change; 
                
                res.status = 200;
                res.set_content(response.dump(), "application/json");
            } else {
                res.status = 401;
                res.set_content("{\"error\":\"Invalid username or password.\"}", "application/json");
            }
        } catch (...) {
            res.status = 400;
            res.set_content("{\"error\":\"Bad request payload.\"}", "application/json");
        }
    });

    // ==============================================================================
    // IDENTITY & ACCESS MANAGEMENT (REST API)
    // Routes designed specifically for the Avalonia Native Admin Panel.
    // ==============================================================================

    // READ: Fetch the entire ledger
    svr.Get("/api/v1/users", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }
        std::string json_ledger = get_all_users_json();
        res.set_content(json_ledger, "application/json");
    });

    // CREATE: Provision a new operator directly (via Desktop Client)
    svr.Post("/api/v1/users", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }

        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string full_name = json_body.value("full_name", "");
            std::string email = json_body.value("email_address", "");
            std::string username = json_body.value("username", "");
            std::string role = json_body.value("role", "User");

            // Generate a random temporary 6-digit PIN
            auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count() ^ std::random_device{}();
            std::mt19937 gen(seed);
            std::uniform_int_distribution<> dist(100000, 999999);
            std::string temp_pin = std::to_string(dist(gen));

            // Generate the WireGuard Jail profile payload
            MobileSubToken token = generate_mobile_sub_token(username, temp_pin, true);

            // Hash the PIN for the database
            char hashed_pw[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(hashed_pw, temp_pin.c_str(), temp_pin.length(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
                res.status = 500;
                res.set_content("{\"error\":\"Crypto failure.\"}", "application/json");
                return;
            }

            if (provision_new_user(username, full_name, email, role, std::string(hashed_pw), token.public_key_b64, token.assigned_ip)) {
                
                // Add the jail profile to wg0.conf
                std::string wg_conf_path = "/data/vpn_config/wg_confs/wg0.conf";
                std::string builder_block = "\n# [CTS Builder Temporary Access]\n"
                                           "[Peer]\n"
                                           "PublicKey = " + token.public_key_b64 + "\n"
                                           "AllowedIPs = " + token.assigned_ip + "/32\n";

                std::ofstream wg_file(wg_conf_path, std::ios::app);
                if (wg_file.is_open()) {
                    wg_file << builder_block;
                    wg_file.close();
                }

                // Trigger Gentoo daemon reload
                std::ofstream flag_file("/data/config/reload.flag");
                if (flag_file.is_open()) {
                    flag_file << "reload";
                    flag_file.close();
                }

                // Dispatch the email with the encrypted CAI attachment
                EmailClient::send_welcome_email(email, username, full_name, temp_pin, token.encrypted_qr_payload_b64);

                global_state_version++; // Trigger C# UI synchronisation
                res.status = 200;
                res.set_content("{\"status\":\"success\"}", "application/json");
                std::cout << "[CTS-API] Successfully provisioned user: " << username << "\n";
            } else {
                res.status = 400;
                res.set_content("{\"error\":\"Database rejection. Check unique constraints.\"}", "application/json");
            }
        } catch (...) {
            res.status = 400;
            res.set_content("{\"error\":\"Bad request.\"}", "application/json");
        }
    });

    // UPDATE: Modify Profile 
    svr.Put(R"(/api/v1/users/([^/]+))", [](const httplib::Request& req, httplib::Response& res) {
        std::string user_id = req.matches[1];
        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string full_name = json_body.value("full_name", "");
            std::string role = json_body.value("role", "");
            std::string photo_path = json_body.value("profile_photo_path", "");
            
            if (update_user_profile(user_id, full_name, role, photo_path)) {
                global_state_version++; // Trigger C# UI synchronisation
                res.status = 200;
                res.set_content("{\"status\":\"success\"}", "application/json");
            } else {
                res.status = 400;
                res.set_content("{\"error\":\"Update failed.\"}", "application/json");
            }
        } catch (...) { res.status = 400; res.set_content("{\"error\":\"Bad request.\"}", "application/json"); }
    });

    // READ: Securely stream the user's avatar PNG to the frontend
    svr.Get(R"(/api/v1/users/([^/]+)/avatar)", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }

        std::string user_id = req.matches[1];
        std::string photo_path = get_user_photo_path(user_id);

        if (photo_path.empty() || !std::filesystem::exists(photo_path)) {
            res.status = 404;
            res.set_content("404 - Avatar not found", "text/plain");
            return;
        }

        std::ifstream file(photo_path, std::ios::binary);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            // Assuming PNG based on your architecture requirements
            res.set_content(buffer.str(), "image/png"); 
        } else {
            res.status = 500;
            res.set_content("500 - Failed to read image from disk", "text/plain");
        }
    });

    // CREATE/UPDATE: Securely upload and verify an avatar payload
    svr.Post(R"(/api/v1/users/([^/]+)/avatar)", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }

        std::string user_id = req.matches[1];
        
        // 1. Security Check: Validate payload size (Max 5MB to prevent memory exhaustion)
        if (req.body.length() > 5 * 1024 * 1024) {
            res.status = 413;
            res.set_content("{\"error\":\"Payload too large. 5MB maximum.\"}", "application/json");
            std::cerr << "[CTS-API] SECURITY WARNING: Oversized file upload attempt intercepted.\n";
            return;
        }

        // 2. Security Check: Validate Magic Bytes (Is it actually an image?)
        std::string file_extension = "";
        if (!is_valid_image_payload(req.body, file_extension)) {
            res.status = 415;
            res.set_content("{\"error\":\"Invalid file signature. Only raw PNG or JPG binaries are permitted.\"}", "application/json");
            std::cerr << "[CTS-API] SECURITY WARNING: Malicious or invalid file type intercepted.\n";
            return;
        }

        // 3. Prepare the Gentoo Filesystem (ensure directory exists)
        std::string target_dir = "/data/avatars";
        std::filesystem::create_directories(target_dir);
        std::string target_path = target_dir + "/" + user_id + file_extension;

        // 4. Lock the binary data to disk
        std::ofstream out_file(target_path, std::ios::binary | std::ios::trunc);
        if (out_file.is_open()) {
            out_file.write(req.body.c_str(), req.body.length());
            out_file.close();

            // 5. Update PostgreSQL
            if (update_user_photo_path(user_id, target_path)) {
                global_state_version++; // Trigger UI synchronisation
                res.status = 200;
                res.set_content("{\"status\":\"success\", \"message\":\"Avatar secured and locked to profile.\"}", "application/json");
                std::cout << "[CTS-API] SUCCESS: Avatar securely uploaded for user ID: " << user_id << "\n";
            } else {
                res.status = 500;
                res.set_content("{\"error\":\"Failed to update database.\"}", "application/json");
            }
        } else {
            res.status = 500;
            res.set_content("{\"error\":\"Server filesystem error.\"}", "application/json");
        }
    });

    // ==============================================================================
    // FEDERATED IDENTITY: AGNOSTIC ENTITLEMENTS (GET)
    // Aggregates entitlement schemas from all downstream Docker apps.
    // Property of Cel-Tech-Serv Pty Ltd.
    // ==============================================================================
    svr.Get(R"(/api/v1/users/([^/]+)/entitlements)", [](const httplib::Request &req, httplib::Response &res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }

        std::string target_user = req.matches[1];
        nlohmann::json aggregated_entitlements = nlohmann::json::array();
        std::string auth_header = req.get_header_value("Authorization");

        // Loop through all installed apps in the JSON config and ask for their entitlements
        for (const auto& [prefix, target] : gateway_routes) {
            httplib::Client cli(target.host, target.port);
            cli.set_connection_timeout(2, 0); 
            httplib::Headers headers = {{"Authorization", auth_header}};
            
            // Query downstream apps using a standardized federated path
            auto proxy_res = cli.Get(prefix + "/entitlements/" + target_user, headers);
            
            if (proxy_res && proxy_res->status == 200) {
                try {
                    auto json_res = nlohmann::json::parse(proxy_res->body);
                    if (json_res.contains("entitlements")) {
                        for (const auto& ent : json_res["entitlements"]) aggregated_entitlements.push_back(ent);
                    }
                } catch (...) {}
            }
        }

        nlohmann::json response = {
            {"status", "SUCCESS"}, 
            {"entitlements", aggregated_entitlements},
            {"vendor", "CTS Zero Trust Engine Software Master SDUI"},
            {"copyright", "Cel-Tech-Serv Pty Ltd"}
        };
        res.set_content(response.dump(), "application/json");
    });

    // ==============================================================================
    // FEDERATED IDENTITY: AGNOSTIC ENTITLEMENTS (PUT)
    // Routes the entitlement toggle directly to the app that manages it.
    // ==============================================================================
    svr.Put(R"(/api/v1/users/([^/]+)/entitlements/([^/]+))", [](const httplib::Request &req, httplib::Response &res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }

        std::string target_user = req.matches[1];
        std::string target_app = req.matches[2];
        std::string auth_header = req.get_header_value("Authorization");
        bool routed = false;

        for (const auto& [prefix, target] : gateway_routes) {
            // Check if this downstream route is responsible for this app_id
            if (std::find(target.managed_apps.begin(), target.managed_apps.end(), target_app) != target.managed_apps.end()) {
                
                httplib::Client cli(target.host, target.port);
                httplib::Headers headers = {
                    {"Authorization", auth_header},
                    {"Content-Type", "application/json"}
                };
                
                // Route the JIT provisioning payload to the specific downstream app
                auto proxy_res = cli.Put(prefix + "/entitlements/" + target_user + "/" + target_app, headers, req.body, "application/json");
                
                if (proxy_res) {
                    res.status = proxy_res->status;
                    res.set_content(proxy_res->body, "application/json");
                } else {
                    res.status = 502;
                    res.set_content("{\"error\":\"Bad Gateway. Target app container unreachable.\"}", "application/json");
                }
                routed = true;
                break;
            }
        }

        if (!routed) {
            res.status = 404;
            res.set_content("{\"error\":\"App ID not mapped in gateway_routes.json\"}", "application/json");
        }
    });

    // DELETE: Permanently Remove Operator
    svr.Delete(R"(/api/v1/users/([^/]+))", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }

        std::string user_id = req.matches[1];
        if (delete_user(user_id)) {
            // THE FIX: Trigger the cleanup routine to purge dead keys instantly
            sync_wireguard_conf();
            
            global_state_version++; // Trigger C# UI synchronisation
            res.status = 200;
            res.set_content("{\"status\":\"success\"}", "application/json");
            std::cout << "[CTS-API] SUCCESS: Permanently deleted user ID: " << user_id << "\n";
        } else {
            res.status = 400;
            res.set_content("{\"error\":\"Deletion failed.\"}", "application/json");
        }
    });



    // UPDATE: Toggle User Status (Suspend/Activate)
    svr.Put(R"(/api/v1/users/([^/]+)/status)", [](const httplib::Request& req, httplib::Response& res) {
        std::string user_id = req.matches[1];
        try {
            auto json_body = nlohmann::json::parse(req.body);
            bool is_active = json_body.value("is_active", true);
            
            if (toggle_user_status(user_id, is_active)) {
                global_state_version++; // Trigger C# UI synchronisation
                res.status = 200;
                res.set_content("{\"status\":\"success\"}", "application/json");
            } else {
                res.status = 400;
                res.set_content("{\"error\":\"Toggle failed.\"}", "application/json");
            }
        } catch (...) { res.status = 400; res.set_content("{\"error\":\"Bad request.\"}", "application/json"); }
    });

    // ==============================================================================
    // IDENTITY MANAGEMENT: FETCH USER EXTENSIONS (SDUI TABS)
    // Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
    // ==============================================================================
    // INSTRUCTIONS FOR COPYING:
    // 1. This dynamically generates a TabControl payload by reading modular plugin 
    //    files provided by OSL, OSSC, or CelAI VMS.
    // ==============================================================================
    
    svr.Get(R"(/api/v1/users/([^/]+)/extensions)", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized.\"}", "application/json");
            return;
        }

        std::string target_user_id = req.matches[1];
        
        // Initialise the master TabControl payload with brand protection
        nlohmann::json extension_payload;
        extension_payload["type"] = "TabControl";
        extension_payload["children"] = nlohmann::json::array();
        extension_payload["metadata"]["provider"] = "Cel-Tech-Serv Pty Ltd";

        // Aggregate extension tabs from the isolated apps (e.g., OSL, OSSC)
        std::string extensions_dir = "/data/config/user_extensions.d/";
        
        // Ensure the directory exists to prevent filesystem errors
        if (!std::filesystem::exists(extensions_dir)) {
            std::filesystem::create_directories(extensions_dir);
        }

        if (std::filesystem::exists(extensions_dir)) {
            for (const auto& entry : std::filesystem::directory_iterator(extensions_dir)) {
                if (entry.path().extension() == ".json") {
                    std::ifstream ext_file(entry.path());
                    if (ext_file.is_open()) {
                        try {
                            nlohmann::json ext_json;
                            ext_file >> ext_json;
                            
                            // Inject the parsed TabPanel into the master TabControl
                            extension_payload["children"].push_back(ext_json); 
                        } catch (...) {
                            std::cerr << "[CTS-API] WARNING: Failed to parse user extension file: " << entry.path() << "\n";
                        }
                    }
                }
            }
        }

        res.status = 200;
        res.set_content(extension_payload.dump(), "application/json");
    });

    // UPDATE: Mandatory Password Reset Processing
    svr.Put(R"(/api/v1/users/([^/]+)/password)", [](const httplib::Request& req, httplib::Response& res) {
        std::string target_user = req.matches[1];
        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string new_pass = json_body.value("new_password", json_body.value("password", ""));

            if (new_pass.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"Password payload missing or empty.\"}", "application/json");
                return;
            }

            if (update_user_password(target_user, new_pass)) {
                global_state_version++; // Trigger C# UI synchronisation
                res.status = 200;
                res.set_content("{\"status\":\"success\", \"message\":\"Password updated successfully.\"}", "application/json");
                std::cout << "[CTS-API] SUCCESS: Password locked in for " << target_user << ". Account secured.\n";
            } else {
                res.status = 500;
                res.set_content("{\"error\":\"Failed to commit password to database.\"}", "application/json");
            }
        } catch (...) {
            res.status = 400;
            res.set_content("{\"error\":\"Bad request payload.\"}", "application/json");
        }
    });

    // CREATE: External Admin Provisioning Route (e.g. from generic web forms)
    svr.Post("/api/v1/admin/provision", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized. Admin token required.\"}", "application/json");
            return;
        }

        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string target_email = json_body.value("email", "");
            std::string target_user = json_body.value("username", "");

            if (target_email.empty() || target_user.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"Email and username required.\"}", "application/json");
                return;
            }

            // Generate an ad-hoc temporary Builder PIN
            auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count() ^ std::random_device{}();
            std::mt19937 gen(seed);
            std::uniform_int_distribution<> dist(100000, 999999);
            std::string new_pin = std::to_string(dist(gen));

            std::lock_guard<std::mutex> lock(bootstrap_mutex);
            current_builders_pin = new_pin;
            open_web_interface_active = true;

            std::string subject = "CTS Zero Trust Provisioning - Initial Credentials";
            std::string body = "<html><body style='font-family:sans-serif;'>"
                               "<h2 style='color:#3f5bca;'>Welcome to Cel-Tech-Serv</h2>"
                               "<p>An administrator has provisioned your Zero Trust account.</p>"
                               "<p>Your temporary Builder's PIN is: <b style='font-size:24px; color:#007b5f;'>" + new_pin + "</b></p>"
                               "<p>Please navigate immediately to <b>https://cts.celtechserv.com</b> on your target machine to claim your cryptographic payload and download the desktop client.</p>"
                               "</body></html>";
            
            EmailClient::send_smtp_email(target_email, subject, body);

            global_state_version++; // State change (web portal opened)
            res.status = 200;
            res.set_content("{\"status\":\"success\", \"message\":\"User provisioned and gateway unlocked.\"}", "application/json");

        } catch (...) {
            res.status = 400;
            res.set_content("{\"error\":\"Bad request.\"}", "application/json");
        }
    });

    // ==============================================================================
    // FALLBACK / LEGACY ROUTES
    // ==============================================================================

    // Legacy standard user handover (pre-REST identity management)
    svr.Post("/user-claim", [](const httplib::Request& req, httplib::Response& res) {
        if (!open_web_interface_active) {
            res.status = 403;
            res.set_content("{\"error\":\"Bootstrap phase locked.\"}", "application/json");
            return;
        }

        try {
            auto json_body = nlohmann::json::parse(req.body);
            std::string provided_pin = json_body.value("pin", "");
            std::string username = json_body.value("username", "");
            std::string password = json_body.value("pass", "");

            if (provided_pin.empty() || username.empty() || password.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"Please fill out all fields.\"}", "application/json");
                return;
            }

            std::lock_guard<std::mutex> lock(bootstrap_mutex);
            if (provided_pin != current_builders_pin || current_builders_pin.empty()) {
                res.status = 401;
                res.set_content("{\"error\":\"Invalid PIN.\"}", "application/json");
                return;
            }

            MobileSubToken token = generate_mobile_sub_token(username, password, true);

            char hashed_pw[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(hashed_pw, password.c_str(), password.length(), 
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
                throw std::runtime_error("Out of memory hashing password");
            }

            extern std::string get_db_string(); 
            pqxx::connection conn(get_db_string());
            pqxx::work W(conn);
            W.exec_params(
                "INSERT INTO users (username, full_name, password_hash, role, temp_vpn_public_key, temp_vpn_ip_address, must_change_password) "
                "VALUES ($1, 'CTS User', $2, 'User', $3, $4, TRUE)",
                username, std::string(hashed_pw), token.public_key_b64, token.assigned_ip
            );
            W.commit();

            std::string wg_conf_path = "/data/vpn_config/wg_confs/wg0.conf";
            current_builder_wg_block = "\n# [CTS Builder Temporary Access]\n"
                                       "[Peer]\n"
                                       "PublicKey = " + token.public_key_b64 + "\n"
                                       "AllowedIPs = " + token.assigned_ip + "/32\n";

            std::ofstream wg_file(wg_conf_path, std::ios::app);
            if (wg_file.is_open()) {
                wg_file << current_builder_wg_block;
                wg_file.close();
            }

            std::ofstream flag_file("/data/config/reload.flag");
            if (flag_file.is_open()) {
                flag_file << "reload";
                flag_file.close();
            }

            current_builders_pin = password; 
            open_web_interface_active = false; 

            global_state_version++; // Notify system of database insertion
            
            nlohmann::json response;
            response["status"] = "success";
            response["cai_payload"] = token.encrypted_qr_payload_b64;
            res.set_content(response.dump(), "application/json");

        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content("{\"error\":\"Failed to process user handover.\"}", "application/json");
        }
    });

    // Client setup executable downloader
    svr.Get("/download/client", [](const httplib::Request& req, httplib::Response& res) {
        std::string installer_path = "./public/CTS_Installer.exe"; 
        std::ifstream file(installer_path, std::ios::binary);
        
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            res.set_content(buffer.str(), "application/vnd.microsoft.portable-executable");
            res.set_header("Content-Disposition", "attachment; filename=\"CTS_ZeroTrust_Client_Setup.exe\"");
        } else {
            res.status = 404;
            res.set_content("404 - The CTS Client Installer is not currently available on the server.", "text/plain");
        }
    });

    // ==============================================================================
    // ROOT WEBPAGE ROUTER (FALLBACK WEB UI)
    // Determines what HTML is served based on the active security state
    // ==============================================================================
    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        if (!open_web_interface_active) {
            res.status = 403;
            res.set_content("<html><body style='background:#0f172a;color:#d4af37;text-align:center;padding-top:50px;font-family:sans-serif;'><h1>403 Forbidden</h1><p>The CTS Zero Trust Gateway is currently locked.</p></body></html>", "text/html");
            return;
        }

        extern bool is_master_admin_present();
        if (is_master_admin_present()) {
            std::ifstream file("./public/user_onboarding.html");
            if (file.is_open()) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                res.set_content(buffer.str(), "text/html");
            } else {
                res.status = 404;
                res.set_content("404 - User Portal HTML not found.", "text/plain");
            }
            return;
        }

        std::ifstream file("./public/index.html");
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            res.set_content(buffer.str(), "text/html");
        } else {
            res.status = 404;
            res.set_content("404 - HTML file not found at ./public/index.html inside container.", "text/plain");
        }
    });

    // ==============================================================================
    // BOOTSTRAP STATE INITIALISATION
    // ==============================================================================
    
    int user_count = get_total_user_count();
    
    std::cout << "\n[DEBUG-BOOT] Engine spinning up. Polling PostgreSQL for user_count...\n"
              << "[DEBUG-BOOT] get_total_user_count() returned: " << user_count << "\n";
    std::cout.flush();

    if (user_count == 0) {
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count() ^ std::random_device{}();
        std::mt19937 gen(seed);
        std::uniform_int_distribution<> dist(100000, 999999);
        current_builders_pin = std::to_string(dist(gen));
        open_web_interface_active = true;

        std::cout << "\n===============================================================\n"
                  << " [CTS SECURITY] INITIAL SETUP: ZERO-TRUST BOOTSTRAP ACTIVE\n"
                  << " [CTS SECURITY] TEMPORARY BUILDER'S PIN: " << current_builders_pin << "\n"
                  << "===============================================================\n\n";
    } else {
        current_builders_pin = "";
        open_web_interface_active = false;
        
        std::cout << "\n===============================================================\n"
                  << " [CTS SECURITY] DATABASE POPULATED. GATEWAY LOCKED.\n"
                  << " [CTS SECURITY] Awaiting Admin API Provisioning Event.\n"
                  << "===============================================================\n\n";
    }
    
    std::cout << "[CTS-API] Gateway engine listening on port 8088\n";
    std::cout.flush(); 
    svr.listen("0.0.0.0", 8088);

    return 0;
}