#pragma once

#ifndef DB_MANAGER_H
#define DB_MANAGER_H

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "utils.h"

namespace db_manager {

    struct Bip448NonceState {
        std::vector<unsigned char> public_nonce;
        std::string public_nonce_hex;
        std::unique_ptr<utils::chacha20_poly1305_encrypted_data> encrypted_secnonce;
        std::optional<std::string> challenge;
        std::optional<int> negate_seckey;
        std::optional<std::string> partial_sig;
    };

    void serialize(const utils::chacha20_poly1305_encrypted_data* src, unsigned char* buffer, size_t* serialized_len);

    bool initialize_database(std::string& error_message);

    bool deserialize(const unsigned char* buffer, utils::chacha20_poly1305_encrypted_data* dest);

    bool save_generated_public_key(
        const utils::chacha20_poly1305_encrypted_data& encrypted_keypair, 
        unsigned char* server_public_key, size_t server_public_key_size,
        const std::string& statechain_id,
        std::string& error_message);

    bool load_generated_keypair(
        const std::string& statechain_id, 
        std::unique_ptr<utils::chacha20_poly1305_encrypted_data>& encrypted_keypair,
        std::string& error_message);

    bool get_bip448_public_nonce(
        const std::string& statechain_id,
        const std::string& signing_id,
        bool& found,
        std::string& public_nonce_hex,
        std::string& error_message);

    bool insert_bip448_nonce_state(
        const std::string& statechain_id,
        const std::string& signing_id,
        unsigned char* serialized_server_pubnonce, const size_t serialized_server_pubnonce_size,
        const utils::chacha20_poly1305_encrypted_data& encrypted_secnonce,
        bool& inserted,
        std::string& error_message);

    bool load_bip448_nonce_state(
        const std::string& statechain_id,
        const std::string& signing_id,
        bool& found,
        Bip448NonceState& state,
        std::string& error_message);

    bool claim_bip448_nonce_challenge(
        const std::string& statechain_id,
        const std::string& signing_id,
        const std::string& challenge,
        int negate_seckey,
        bool& claimed,
        std::string& error_message);

    bool save_bip448_partial_signature(
        const std::string& statechain_id,
        const std::string& signing_id,
        const std::string& challenge,
        int negate_seckey,
        const std::string& partial_sig,
        bool& saved,
        std::string& error_message);

    bool update_sig_count(const std::string& statechain_id);

    bool signature_count(const std::string& statechain_id, int& sig_count, std::string& error_message);

    bool update_sealed_keypair(
        const utils::chacha20_poly1305_encrypted_data& encrypted_keypair, 
        unsigned char* server_public_key, size_t server_public_key_size,
        const std::string& statechain_id,
        std::string& error_message);

    bool delete_statechain(const std::string& statechain_id);
}

#endif // DB_MANAGER_H
