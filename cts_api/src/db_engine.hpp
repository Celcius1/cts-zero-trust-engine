// ==============================================================================
// CTS ZERO TRUST ENGINE - DATABASE ENGINE (HEADER)
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
#pragma once
#include <string>

// Authenticates a user against the PostgreSQL database.
// If successful, returns true, populates out_role, and sets out_must_change.
bool authenticate_user(const std::string& username, const std::string& password, std::string& out_role, bool& out_must_change);

// Updates the user's password and clears the must_change_password flag.
bool update_user_password(const std::string& username, const std::string& new_password);

// Queries the PostgreSQL database to see if any users exist yet.
int get_total_user_count();

// Checks if the root System Administrator exists to spring the security trap
bool is_master_admin_present();

// Fetches the entire user ledger as a JSON string
std::string get_all_users_json();

// Injects a newly provisioned user directly into the database
bool provision_new_user(const std::string& username, const std::string& full_name, const std::string& email, const std::string& role, const std::string& temp_pw_hash, const std::string& temp_pub_key, const std::string& temp_ip);

// Updates an existing user's profile and photo path
bool update_user_profile(const std::string& user_id, const std::string& full_name, const std::string& role, const std::string& photo_path);

// Toggles a user's active status
bool toggle_user_status(const std::string& user_id, bool is_active);

// Permanently deletes a user from the ledger
bool delete_user(const std::string& user_id);

// Retrieves the raw filesystem path for a user's avatar
std::string get_user_photo_path(const std::string& user_id);

// Updates just the profile photo path for a user
bool update_user_photo_path(const std::string& user_id, const std::string& photo_path);

// Rebuilds wg0.conf from the database and reloads the daemon
bool sync_wireguard_conf();