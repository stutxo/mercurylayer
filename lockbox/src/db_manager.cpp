#include "db_manager.h"

#include <cassert>
#include <iostream>
#include <memory>
#include <pqxx/pqxx>
#include <string>
#include <toml++/toml.h>
#include <vector>
#include "utils.h"

namespace db_manager {

    std::string getDatabaseConnectionString() {
        return utils::getStringConfigVar(utils::DATABASE_URL);
    }

    namespace {
        void ensure_generated_public_key_table(pqxx::work& txn) {
            txn.exec(
                "CREATE TABLE IF NOT EXISTS generated_public_key ( "
                "id SERIAL PRIMARY KEY, "
                "statechain_id varchar(50), "
                "sealed_keypair BYTEA, "
                "public_key BYTEA UNIQUE, "
                "sig_count INTEGER DEFAULT 0);"
            );
        }

        void ensure_bip448_nonce_state_table(pqxx::work& txn) {
            txn.exec(
                "CREATE TABLE IF NOT EXISTS bip448_nonce_state ( "
                "id SERIAL PRIMARY KEY, "
                "statechain_id varchar(50) NOT NULL, "
                "signing_id varchar(64) NOT NULL, "
                "public_nonce BYTEA NOT NULL, "
                "sealed_secnonce BYTEA NOT NULL, "
                "challenge varchar(64) NULL, "
                "negate_seckey INTEGER NULL, "
                "partial_sig varchar NULL, "
                "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), "
                "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), "
                "CONSTRAINT bip448_nonce_state_unique UNIQUE (statechain_id, signing_id), "
                "CONSTRAINT bip448_nonce_state_signing_id_check CHECK (signing_id ~ '^[0-9a-f]{64}$'), "
                "CONSTRAINT bip448_nonce_state_challenge_check CHECK (challenge IS NULL OR challenge ~ '^[0-9a-f]{64}$'), "
                "CONSTRAINT bip448_nonce_state_negate_check CHECK (negate_seckey IS NULL OR negate_seckey IN (0, 1)), "
                "CONSTRAINT bip448_nonce_state_claim_check CHECK ((challenge IS NULL AND negate_seckey IS NULL AND partial_sig IS NULL) OR (challenge IS NOT NULL AND negate_seckey IS NOT NULL)) "
                ");"
            );
        }

        std::vector<unsigned char> serialize_encrypted_data(const utils::chacha20_poly1305_encrypted_data& encrypted_data) {
            size_t serialized_len = 0;
            size_t buffer_size = sizeof(encrypted_data.data_len) + sizeof(encrypted_data.nonce) + sizeof(encrypted_data.mac) + encrypted_data.data_len;
            std::vector<unsigned char> buffer(buffer_size);

            serialize(&encrypted_data, buffer.data(), &serialized_len);
            assert(serialized_len == buffer_size);

            return buffer;
        }

        std::vector<unsigned char> bytea_field_to_vector(const pqxx::field& field) {
            auto bytes = field.as<std::basic_string<std::byte>>();
            std::vector<unsigned char> result(bytes.size());
            memcpy(result.data(), bytes.data(), bytes.size());
            return result;
        }

        std::string hex_without_prefix(const unsigned char* data, size_t data_size) {
            std::string hex = utils::key_to_string(data, data_size);
            if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) {
                return hex.substr(2);
            }
            return hex;
        }

        void populate_bip448_nonce_state(const pqxx::row& row, Bip448NonceState& state) {
            state.public_nonce = bytea_field_to_vector(row["public_nonce"]);
            state.public_nonce_hex = hex_without_prefix(state.public_nonce.data(), state.public_nonce.size());

            state.encrypted_secnonce = std::make_unique<utils::chacha20_poly1305_encrypted_data>();
            auto sealed_secnonce = bytea_field_to_vector(row["sealed_secnonce"]);
            if (!deserialize(sealed_secnonce.data(), state.encrypted_secnonce.get())) {
                state.encrypted_secnonce.reset();
            }

            if (row["challenge"].is_null()) {
                state.challenge.reset();
            } else {
                state.challenge = row["challenge"].as<std::string>();
            }

            if (row["negate_seckey"].is_null()) {
                state.negate_seckey.reset();
            } else {
                state.negate_seckey = row["negate_seckey"].as<int>();
            }

            if (row["partial_sig"].is_null()) {
                state.partial_sig.reset();
            } else {
                state.partial_sig = row["partial_sig"].as<std::string>();
            }
        }
    } // namespace

    bool initialize_database(std::string& error_message) {
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (!conn.is_open()) {
                error_message = "Failed to connect to the database!";
                return false;
            }

            pqxx::work txn(conn);
            ensure_generated_public_key_table(txn);
            ensure_bip448_nonce_state_table(txn);
            txn.commit();
            conn.close();
            return true;
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    // Assumes the buffer is large enough. In a real application, ensure buffer safety.
    void serialize(const utils::chacha20_poly1305_encrypted_data* src, unsigned char* buffer, size_t* serialized_len) {
        // Copy `data_len`, `nonce`, and `mac` directly
        size_t offset = 0;
        memcpy(buffer + offset, &src->data_len, sizeof(src->data_len));
        offset += sizeof(src->data_len);

        memcpy(buffer + offset, src->nonce, sizeof(src->nonce));
        offset += sizeof(src->nonce);

        memcpy(buffer + offset, src->mac, sizeof(src->mac));
        offset += sizeof(src->mac);

        // Now copy dynamic `data`
        memcpy(buffer + offset, src->data, src->data_len);
        offset += src->data_len;

        *serialized_len = offset;
    }

    // Returns a newly allocated structure that must be freed by the caller.
    bool deserialize(const unsigned char* buffer, utils::chacha20_poly1305_encrypted_data* dest) {

        if (!dest) return false;

        size_t offset = 0;
        memcpy(&dest->data_len, buffer + offset, sizeof(dest->data_len));
        offset += sizeof(dest->data_len);

        memcpy(dest->nonce, buffer + offset, sizeof(dest->nonce));
        offset += sizeof(dest->nonce);

        memcpy(dest->mac, buffer + offset, sizeof(dest->mac));
        offset += sizeof(dest->mac);

        dest->data = new unsigned char[dest->data_len];
        if (!dest->data) {
            return false; // NULL;
        }
        memcpy(dest->data, buffer + offset, dest->data_len);

        return true;
    }

    bool save_generated_public_key(
        const utils::chacha20_poly1305_encrypted_data& encrypted_keypair, 
        unsigned char* server_public_key, size_t server_public_key_size,
        const std::string& statechain_id,
        std::string& error_message) {

        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                size_t serialized_len = 0;

                size_t bufferSize = sizeof(encrypted_keypair.data_len) + sizeof(encrypted_keypair.nonce) + sizeof(encrypted_keypair.mac) + encrypted_keypair.data_len;
                unsigned char* buffer = (unsigned char*) malloc(bufferSize);

                if (!buffer) {
                    error_message = "Failed to allocate memory for serialization!";
                    return false;
                }

                serialize(&encrypted_keypair, buffer, &serialized_len);
                assert(serialized_len == bufferSize);

                std::basic_string_view<std::byte> sealed_data_view(reinterpret_cast<std::byte*>(buffer), bufferSize);
                std::basic_string_view<std::byte> public_key_data_view(reinterpret_cast<std::byte*>(server_public_key), server_public_key_size);

                std::string insert_query =
                    "INSERT INTO generated_public_key (sealed_keypair, public_key, statechain_id) VALUES ($1, $2, $3);";
                pqxx::work txn2(conn);

                txn2.exec_params(insert_query, sealed_data_view, public_key_data_view, statechain_id);
                txn2.commit();

                conn.close();
                return true;

                return true;
            } else {
                error_message = "Failed to connect to the database!";
                return false;
            }
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }

        return true;
    }

    bool load_generated_keypair(
        const std::string& statechain_id, 
        std::unique_ptr<utils::chacha20_poly1305_encrypted_data>& encrypted_keypair,
        std::string& error_message)
    {
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                std::string sealed_keypair_query =
                    "SELECT sealed_keypair FROM generated_public_key WHERE statechain_id = $1;";

                pqxx::nontransaction ntxn(conn);

                conn.prepare("load_generated_keypair_query", sealed_keypair_query);

                pqxx::result result = ntxn.exec_prepared("load_generated_keypair_query", statechain_id);

                if (!result.empty()) {
                    auto sealed_keypair_field = result[0]["sealed_keypair"];

                    if (sealed_keypair_field.is_null()) {
                        encrypted_keypair.reset();
                    } else if (encrypted_keypair != nullptr) {
                        auto sealed_keypair_view = sealed_keypair_field.as<std::basic_string<std::byte>>();

                        std::vector<unsigned char> sealed_keypair(sealed_keypair_view.size());
                        memcpy(sealed_keypair.data(), sealed_keypair_view.data(), sealed_keypair_view.size());

                        if (!deserialize(sealed_keypair.data(), encrypted_keypair.get())) {
                            error_message = "Failed to deserialize keypair!";
                            return false;
                        }
                    }
                }
                else {
                    error_message = "Failed to retrieve keypair. No data found !";
                    return false;
                }

                conn.close();
                return true;
            } else {
                error_message = "Failed to connect to the database!";
                return false;
            }
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool get_bip448_public_nonce(
        const std::string& statechain_id,
        const std::string& signing_id,
        bool& found,
        std::string& public_nonce_hex,
        std::string& error_message)
    {
        found = false;
        public_nonce_hex.clear();
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (!conn.is_open()) {
                error_message = "Failed to connect to the database!";
                return false;
            }

            pqxx::work txn(conn);

            pqxx::result result = txn.exec_params(
                "SELECT public_nonce FROM bip448_nonce_state WHERE statechain_id = $1 AND signing_id = $2;",
                statechain_id,
                signing_id
            );

            if (!result.empty()) {
                auto public_nonce = bytea_field_to_vector(result[0]["public_nonce"]);
                public_nonce_hex = hex_without_prefix(public_nonce.data(), public_nonce.size());
                found = true;
            }

            txn.commit();
            conn.close();
            return true;
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool insert_bip448_nonce_state(
        const std::string& statechain_id,
        const std::string& signing_id,
        unsigned char* serialized_server_pubnonce, const size_t serialized_server_pubnonce_size,
        const utils::chacha20_poly1305_encrypted_data& encrypted_secnonce,
        bool& inserted,
        std::string& error_message)
    {
        inserted = false;
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (!conn.is_open()) {
                error_message = "Failed to connect to the database!";
                return false;
            }

            auto sealed_secnonce = serialize_encrypted_data(encrypted_secnonce);
            std::basic_string_view<std::byte> public_nonce_view(reinterpret_cast<std::byte*>(serialized_server_pubnonce), serialized_server_pubnonce_size);
            std::basic_string_view<std::byte> sealed_secnonce_view(reinterpret_cast<std::byte*>(sealed_secnonce.data()), sealed_secnonce.size());

            pqxx::work txn(conn);
            pqxx::result result = txn.exec_params(
                "INSERT INTO bip448_nonce_state (statechain_id, signing_id, public_nonce, sealed_secnonce) "
                "VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING 1;",
                statechain_id,
                signing_id,
                public_nonce_view,
                sealed_secnonce_view
            );

            inserted = !result.empty();
            txn.commit();
            conn.close();
            return true;
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool load_bip448_nonce_state(
        const std::string& statechain_id,
        const std::string& signing_id,
        bool& found,
        Bip448NonceState& state,
        std::string& error_message)
    {
        found = false;
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (!conn.is_open()) {
                error_message = "Failed to connect to the database!";
                return false;
            }

            pqxx::work txn(conn);

            pqxx::result result = txn.exec_params(
                "SELECT public_nonce, sealed_secnonce, challenge, negate_seckey, partial_sig "
                "FROM bip448_nonce_state WHERE statechain_id = $1 AND signing_id = $2;",
                statechain_id,
                signing_id
            );

            if (!result.empty()) {
                populate_bip448_nonce_state(result[0], state);
                if (state.encrypted_secnonce == nullptr) {
                    error_message = "Failed to deserialize BIP448 sealed nonce!";
                    return false;
                }
                found = true;
            }

            txn.commit();
            conn.close();
            return true;
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool claim_bip448_nonce_challenge(
        const std::string& statechain_id,
        const std::string& signing_id,
        const std::string& challenge,
        int negate_seckey,
        bool& claimed,
        std::string& error_message)
    {
        claimed = false;
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (!conn.is_open()) {
                error_message = "Failed to connect to the database!";
                return false;
            }

            pqxx::work txn(conn);
            pqxx::result result = txn.exec_params(
                "UPDATE bip448_nonce_state SET challenge = $1, negate_seckey = $2, updated_at = NOW() "
                "WHERE statechain_id = $3 AND signing_id = $4 AND challenge IS NULL AND partial_sig IS NULL "
                "RETURNING 1;",
                challenge,
                negate_seckey,
                statechain_id,
                signing_id
            );

            claimed = !result.empty();
            txn.commit();
            conn.close();
            return true;
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool save_bip448_partial_signature(
        const std::string& statechain_id,
        const std::string& signing_id,
        const std::string& challenge,
        int negate_seckey,
        const std::string& partial_sig,
        bool& saved,
        std::string& error_message)
    {
        saved = false;
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (!conn.is_open()) {
                error_message = "Failed to connect to the database!";
                return false;
            }

            pqxx::work txn(conn);
            pqxx::result saved_result = txn.exec_params(
                "UPDATE bip448_nonce_state SET partial_sig = $1, updated_at = NOW() "
                "WHERE statechain_id = $2 AND signing_id = $3 AND challenge = $4 "
                "AND negate_seckey = $5 AND partial_sig IS NULL RETURNING 1;",
                partial_sig,
                statechain_id,
                signing_id,
                challenge,
                negate_seckey
            );

            if (!saved_result.empty()) {
                pqxx::result count_result = txn.exec_params(
                    "UPDATE generated_public_key SET sig_count = sig_count + 1 WHERE statechain_id = $1 RETURNING 1;",
                    statechain_id
                );

                if (count_result.empty()) {
                    error_message = "Failed to update signature count!";
                    txn.abort();
                    return false;
                }

                saved = true;
            }

            txn.commit();
            conn.close();
            return true;
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool update_sig_count(const std::string& statechain_id) 
    {
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                std::string update_query =
                    "UPDATE generated_public_key SET sig_count = sig_count + 1 WHERE statechain_id = $1;";
                pqxx::work txn(conn);

                txn.exec_params(update_query, statechain_id);
                txn.commit();

                conn.close();
                return true;
            } else {
                return false;
            }
        }
        catch (std::exception const &e)
        {
            return false;
        }
    }

    bool signature_count(const std::string& statechain_id, int& sig_count, std::string& error_message) {

        sig_count = 0;

        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                std::string sig_count_query =
                    "SELECT sig_count FROM generated_public_key WHERE statechain_id = $1;";
            
                pqxx::nontransaction ntxn(conn);

                conn.prepare("sig_count_query", sig_count_query);

                pqxx::result result = ntxn.exec_prepared("sig_count_query", statechain_id);

                if (result.empty()) {
                    error_message = "Signature count not found.";
                    conn.close();
                    return false;
                }

                auto sig_count_field = result[0]["sig_count"];
                if (sig_count_field.is_null()) {
                    error_message = "Signature count is NULL.";
                    conn.close();
                    return false;
                }

                sig_count = sig_count_field.as<int>();
                if (sig_count < 0) {
                    error_message = "Signature count is negative.";
                    sig_count = 0;
                    conn.close();
                    return false;
                }

                conn.close();
                return true;
            } else {
                error_message = "Database connection is not open.";
                return false;
            }
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool update_sealed_keypair(
        const utils::chacha20_poly1305_encrypted_data& encrypted_keypair, 
        unsigned char* server_public_key, size_t server_public_key_size,
        const std::string& statechain_id,
        std::string& error_message) 
    {
        auto database_connection_string = getDatabaseConnectionString();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                std::string insert_query =
                    "UPDATE generated_public_key "
                    "SET sealed_keypair = $1, public_key = $2 "
                    "WHERE statechain_id = $3;";
                pqxx::work txn2(conn);

                size_t serialized_len = 0;

                size_t bufferSize = sizeof(encrypted_keypair.data_len) + sizeof(encrypted_keypair.nonce) + sizeof(encrypted_keypair.mac) + encrypted_keypair.data_len;
                unsigned char* buffer = (unsigned char*) malloc(bufferSize);

                if (!buffer) {
                    error_message = "Failed to allocate memory for serialization!";
                    return false;
                }

                serialize(&encrypted_keypair, buffer, &serialized_len);
                assert(serialized_len == bufferSize);

                std::basic_string_view<std::byte> sealed_data_view(reinterpret_cast<std::byte*>(buffer), bufferSize);
                std::basic_string_view<std::byte> public_key_data_view(reinterpret_cast<std::byte*>(server_public_key), server_public_key_size);

                txn2.exec_params(insert_query, sealed_data_view, public_key_data_view, statechain_id);
                txn2.exec_params("DELETE FROM bip448_nonce_state WHERE statechain_id = $1;", statechain_id);
                txn2.commit();

                conn.close();
                return true;
            } else {
                error_message = "Failed to connect to the database!";
                return false;
            }
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }
    }

    bool delete_statechain(const std::string& statechain_id) {
        auto database_connection_string = getDatabaseConnectionString();

        std::string error_message;
        pqxx::connection conn(database_connection_string);
        if (conn.is_open()) {

            std::string delete_comm =
                "DELETE FROM generated_public_key WHERE statechain_id = $1;";
            pqxx::work txn2(conn);

            txn2.exec_params("DELETE FROM bip448_nonce_state WHERE statechain_id = $1;", statechain_id);
            txn2.exec_params(delete_comm, statechain_id);
            txn2.commit();

            conn.close();

            return true;
        } else {
            return false;
        }
    }
} // namespace db_manager
