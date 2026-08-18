// ==============================================================================
// CTS ZERO TRUST ENGINE - CORE CRYPTOGRAPHY
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================

#include "zero_trust_engine.hpp"
#include <sodium.h>
#include <random>
#include <vector>
#include <cstdlib>
#include "nlohmann/json.hpp"

std::string get_env(const std::string& var, const std::string& default_value) {
    const char* val = std::getenv(var.c_str());
    return val == nullptr ? default_value : std::string(val);
}

MobileSubToken generate_mobile_sub_token(const std::string& username, const std::string& sub_token_password, bool is_jail_profile) {
    MobileSubToken token;
    
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    randombytes_buf(sk, sizeof(sk));
    
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    crypto_scalarmult_base(pk, sk);

    char sk_b64[100];
    char pk_b64[100];
    sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, sizeof(sk), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, sizeof(pk), sodium_base64_VARIANT_ORIGINAL);

    token.public_key_b64 = std::string(pk_b64);

    std::string subnet_prefix = is_jail_profile ? 
                                get_env("VPN_JAIL_SUBNET_PREFIX", "10.13.14.") : 
                                get_env("VPN_TRUSTED_SUBNET_PREFIX", "10.13.13.");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(10, 250);
    token.assigned_ip = subnet_prefix + std::to_string(dist(gen));

    nlohmann::json j;
    j["Application"] = "CTS Zero Trust Engine";
    j["Type"] = is_jail_profile ? "Temporary" : "Permanent";
    j["Username"] = username;
    j["WireGuard"]["PrivateKey"] = sk_b64;
    j["WireGuard"]["Address"] = token.assigned_ip;
    j["WireGuard"]["ServerPublicKey"] = get_env("VPN_SERVER_PUBKEY", "PLACEHOLDER"); 
    j["WireGuard"]["Endpoint"] = get_env("VPN_EXTERNAL_IP", "127.0.0.1") + ":51820";

    std::string json_str = j.dump();

    unsigned char key[crypto_secretbox_KEYBYTES]; 
    unsigned char salt[16]; 
    randombytes_buf(salt, sizeof(salt));

    crypto_generichash(key, sizeof(key),
                       (const unsigned char*)sub_token_password.c_str(), sub_token_password.length(),
                       salt, sizeof(salt));

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(json_str.length() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(), (const unsigned char*)json_str.c_str(), json_str.length(), nonce, key);

    std::vector<unsigned char> final_bin;
    final_bin.insert(final_bin.end(), salt, salt + sizeof(salt));
    final_bin.insert(final_bin.end(), nonce, nonce + sizeof(nonce));
    final_bin.insert(final_bin.end(), ciphertext.begin(), ciphertext.end());

    size_t b64_len = sodium_base64_ENCODED_LEN(final_bin.size(), sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> final_b64(b64_len);
    sodium_bin2base64(final_b64.data(), final_b64.size(), final_bin.data(), final_bin.size(), sodium_base64_VARIANT_ORIGINAL);

    token.encrypted_qr_payload_b64 = std::string(final_b64.data());

    return token;
}