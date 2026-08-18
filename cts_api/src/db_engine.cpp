// ==============================================================================
// CTS ZERO TRUST ENGINE - DATABASE ENGINE
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
#include "db_engine.hpp"
#include <fstream>
#include <pqxx/pqxx>
#include <sodium.h>
#include <iostream>
#include <cstdlib>
#include <thread>
#include <chrono>
#include "nlohmann/json.hpp" // Required for the new SDUI ledger parsing

// ==============================================================================
// CONNECTION STRING BUILDER
// (Must be defined at the top so subsequent functions can call it)
// ==============================================================================
std::string get_db_string() {
    auto get_env = [](const char* name, const char* def) {
        const char* val = std::getenv(name);
        return val ? std::string(val) : std::string(def);
    };
    
    std::string host = get_env("POSTGRES_HOST", "cts-db"); 
    std::string user = get_env("POSTGRES_USER", "postgres");
    std::string pass = get_env("POSTGRES_PASSWORD", "password");
    std::string db   = get_env("POSTGRES_DB", "cts_zero_trust");
    std::string port = get_env("POSTGRES_PORT", "5432");

    return "dbname=" + db + " user=" + user + " password=" + pass + " host=" + host + " port=" + port;
}

// ==============================================================================
// COUNT USERS (STATE ENGINE)
// Polls the database until init_schema.sql finishes executing.
// ==============================================================================
int get_total_user_count() {
    int retries = 15;
    
    while (retries > 0) {
        try {
            pqxx::connection conn(get_db_string());
            pqxx::nontransaction N(conn);
            
            pqxx::result res = N.exec("SELECT COUNT(*) FROM users");
            if (!res.empty()) {
                std::cout << "[CTS_DB] Database stabilized and schema verified.\n";
                return res[0][0].as<int>();
            }
        } catch (const std::exception& e) {
            std::cout << "[CTS_DB] Waiting for init_schema.sql to finish generating tables... (" << retries << " attempts left)\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
            retries--;
        }
    }
    
    std::cerr << "[CTS_DB] PANIC: Database failed to stabilize after 30 seconds.\n";
    return 999; 
}

// ==============================================================================
// AUTHENTICATE USER (SSO LOGIN) - CEL-TECH-SERV PTY LTD
// ==============================================================================
bool authenticate_user(const std::string& username, const std::string& password, std::string& out_role, bool& out_must_change) {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::nontransaction N(conn);
        
        pqxx::result result = N.exec_params("SELECT password_hash, role, must_change_password FROM users WHERE username = $1", username);

        if (result.empty()) {
            std::cout << "[CTS_DB] Auth rejected: User not found -> " << username << "\n";
            return false;
        }

        std::string stored_hash = result[0]["password_hash"].c_str();

        if (crypto_pwhash_str_verify(stored_hash.c_str(), password.c_str(), password.length()) == 0) {
            out_role = result[0]["role"].c_str();
            out_must_change = result[0]["must_change_password"].as<bool>();
            
            std::cout << "[CTS_DB] Auth success: Verified -> " << username << "\n";
            return true;
        } else {
            std::cout << "[CTS_DB] Auth rejected: Invalid password -> " << username << "\n";
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Authentication SQL failure. " << e.what() << "\n";
        return false;
    }
}

// ==============================================================================
// UPDATE USER PASSWORD - CEL-TECH-SERV PTY LTD
// ==============================================================================
bool update_user_password(const std::string& username, const std::string& new_password) {
    try {
        char hashed_pw[crypto_pwhash_STRBYTES];
        if (crypto_pwhash_str(hashed_pw, new_password.c_str(), new_password.length(), 
                              crypto_pwhash_OPSLIMIT_INTERACTIVE, 
                              crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
            std::cerr << "[CTS_DB] ERROR: Out of memory hashing new password.\n";
            return false;
        }

        pqxx::connection conn(get_db_string());
        pqxx::work W(conn);
        
        pqxx::result res = W.exec_params(
            "UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE username = $2",
            std::string(hashed_pw), username
        );
        
        W.commit();
        return res.affected_rows() > 0;

    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Password update SQL failure. " << e.what() << "\n";
        return false;
    }
}

// ==============================================================================
// SECURITY TRAP: CHECK FOR MASTER ADMIN - CEL-TECH-SERV PTY LTD
// ==============================================================================
bool is_master_admin_present() {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::nontransaction N(conn);
        pqxx::result res = N.exec("SELECT COUNT(*) FROM users WHERE role = 'Administrator'");
        
        return !res.empty() && res[0][0].as<int>() > 0;
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Trap check failed. " << e.what() << "\n";
        return true; 
    }
}

// ==============================================================================
// IDENTITY MANAGEMENT: FETCH LEDGER
// ==============================================================================
std::string get_all_users_json() {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::nontransaction N(conn);
        
        pqxx::result res = N.exec("SELECT user_id, username, full_name, email_address, role, is_active, vpn_ip_address, last_login, profile_photo_path FROM users ORDER BY username ASC");
        
        nlohmann::json users = nlohmann::json::array();
        for (auto row : res) {
            nlohmann::json u;
            u["user_id"] = row["user_id"].c_str();
            u["username"] = row["username"].c_str();
            u["role"] = row["role"].c_str();
            
            // Handle booleans safely
            u["is_active"] = row["is_active"].is_null() ? false : row["is_active"].as<bool>();
            
            // THE FIX: Explicitly assign nullptr to the JSON object to bypass string construction
            if (row["full_name"].is_null()) {
                u["full_name"] = nullptr;
            } else {
                u["full_name"] = row["full_name"].c_str();
            }
            
            if (row["email_address"].is_null()) {
                u["email_address"] = nullptr;
            } else {
                u["email_address"] = row["email_address"].c_str();
            }

            // NEW: Extract the profile photo path safely
            if (row["profile_photo_path"].is_null()) {
                u["profile_photo_path"] = nullptr;
            } else {
                u["profile_photo_path"] = row["profile_photo_path"].c_str();
            }
            
            if (row["vpn_ip_address"].is_null()) {
                u["vpn_ip_address"] = nullptr;
            } else {
                u["vpn_ip_address"] = row["vpn_ip_address"].c_str();
            }
            
            if (row["last_login"].is_null()) {
                u["last_login"] = nullptr;
            } else {
                u["last_login"] = row["last_login"].c_str();
            }
            
            users.push_back(u);
        }
        return users.dump();
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Ledger fetch failed. " << e.what() << "\n";
        return "[]";
    }
}

// ==============================================================================
// IDENTITY MANAGEMENT: PROVISION USER
// ==============================================================================
bool provision_new_user(const std::string& username, const std::string& full_name, const std::string& email, const std::string& role, const std::string& temp_pw_hash, const std::string& temp_pub_key, const std::string& temp_ip) {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::work W(conn);
        W.exec_params(
            "INSERT INTO users (username, full_name, email_address, role, password_hash, temp_vpn_public_key, temp_vpn_ip_address, must_change_password) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)",
            username, full_name, email, role, temp_pw_hash, temp_pub_key, temp_ip
        );
        W.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Provisioning failed. " << e.what() << "\n";
        return false;
    }
}

// ==============================================================================
// IDENTITY MANAGEMENT: UPDATE PROFILE
// ==============================================================================
bool update_user_profile(const std::string& user_id, const std::string& full_name, const std::string& role, const std::string& photo_path) {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::work W(conn);
        pqxx::result res = W.exec_params(
            "UPDATE users SET full_name = $1, role = $2, profile_photo_path = $3 WHERE user_id = $4", 
            full_name, role, photo_path, user_id
        );
        W.commit();
        return res.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Profile update failed. " << e.what() << "\n";
        return false;
    }
}

// ==============================================================================
// IDENTITY MANAGEMENT: TOGGLE STATUS
// ==============================================================================
bool toggle_user_status(const std::string& user_id, bool is_active) {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::work W(conn);
        pqxx::result res = W.exec_params("UPDATE users SET is_active = $1 WHERE user_id = $2", is_active, user_id);
        W.commit();
        return res.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Status toggle failed. " << e.what() << "\n";
        return false;
    }
}

// ==============================================================================
// IDENTITY MANAGEMENT: DELETE USER
// ==============================================================================
bool delete_user(const std::string& user_id) {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::work W(conn);
        pqxx::result res = W.exec_params("DELETE FROM users WHERE user_id = $1", user_id);
        W.commit();
        return res.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: User deletion failed. " << e.what() << "\n";
        return false;
    }
}

// ==============================================================================
// IDENTITY MANAGEMENT: FETCH AVATAR PATH
// ==============================================================================
std::string get_user_photo_path(const std::string& user_id) {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::nontransaction N(conn);
        pqxx::result res = N.exec_params("SELECT profile_photo_path FROM users WHERE user_id = $1", user_id);
        
        if (!res.empty() && !res[0][0].is_null()) {
            return res[0][0].c_str();
        }
        return "";
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Failed to retrieve photo path. " << e.what() << "\n";
        return "";
    }
}

// ==============================================================================
// IDENTITY MANAGEMENT: UPDATE PHOTO PATH
// ==============================================================================
bool update_user_photo_path(const std::string& user_id, const std::string& photo_path) {
    try {
        pqxx::connection conn(get_db_string());
        pqxx::work W(conn);
        pqxx::result res = W.exec_params(
            "UPDATE users SET profile_photo_path = $1 WHERE user_id = $2", 
            photo_path, user_id
        );
        W.commit();
        return res.affected_rows() > 0;
    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: Failed to update photo path. " << e.what() << "\n";
        return false;
    }
}

// ==============================================================================
// CEL-TECH-SERV PTY LTD: WIREGUARD SYNCHRONISATION
// Rebuilds the wg0.conf peers entirely from the PostgreSQL database to purge
// dead jail allocations and deleted users.
// ==============================================================================

bool sync_wireguard_conf() {
    try {
        std::string wg_conf_path = "/data/vpn_config/wg_confs/wg0.conf";
        std::ifstream in(wg_conf_path);
        std::string interface_block = "";
        std::string line;
        
        // 1. Read the file and keep only the [Interface] section
        if (in.is_open()) {
            while (std::getline(in, line)) {
                if (line.find("[Peer]") != std::string::npos) {
                    break; // Stop reading when we hit the first peer
                }
                interface_block += line + "\n";
            }
            in.close();
        } else {
            std::cerr << "[CTS_DB] ERROR: Could not read wg0.conf for synchronisation.\n";
            return false;
        }

        // 2. Query the database for all active VPN keys (Jail and Permanent)
        pqxx::connection conn(get_db_string());
        pqxx::nontransaction N(conn);
        pqxx::result res = N.exec("SELECT username, temp_vpn_public_key, temp_vpn_ip_address, vpn_public_key, vpn_ip_address FROM users");

        std::string new_peers = "";
        for (auto row : res) {
            std::string user = row["username"].c_str();
            
            // Rebuild Jail Profiles
            if (!row["temp_vpn_public_key"].is_null() && !row["temp_vpn_ip_address"].is_null()) {
                new_peers += "\n# [CTS Builder Temporary Access] " + user + "\n";
                new_peers += "[Peer]\n";
                new_peers += "PublicKey = " + std::string(row["temp_vpn_public_key"].c_str()) + "\n";
                new_peers += "AllowedIPs = " + std::string(row["temp_vpn_ip_address"].c_str()) + "/32\n";
            }
            
            // Rebuild Permanent Profiles
            if (!row["vpn_public_key"].is_null() && !row["vpn_ip_address"].is_null()) {
                new_peers += "\n# [CTS Permanent Access] " + user + "\n";
                new_peers += "[Peer]\n";
                new_peers += "PublicKey = " + std::string(row["vpn_public_key"].c_str()) + "\n";
                new_peers += "AllowedIPs = " + std::string(row["vpn_ip_address"].c_str()) + "/32\n";
            }
        }

        // 3. Overwrite the config file with the pristine state
        std::ofstream out(wg_conf_path, std::ios::trunc);
        if (out.is_open()) {
            out << interface_block << new_peers;
            out.close();
        } else {
            std::cerr << "[CTS_DB] ERROR: Could not write to wg0.conf.\n";
            return false;
        }

        // 4. Trigger the Gentoo OpenRC daemon reload
        std::ofstream flag_file("/data/config/reload.flag");
        if (flag_file.is_open()) {
            flag_file << "reload";
            flag_file.close();
        }

        std::cout << "[CTS-API] WireGuard configuration synchronised with database. Dead allocations purged.\n";
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[CTS_DB] ERROR: WireGuard sync failed. " << e.what() << "\n";
        return false;
    }
}