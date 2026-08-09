#include "server.h"
#include <crow.h>
#include <openssl/rand.h>
#include "utils.h"
#include "enclave.h"
#include "google_key_manager.h"
#include "hashicorp_api_key_manager.h"
#include "hashicorp_container_key_manager.h"
#include "filesystem_key_manager.h"
#include "db_manager.h"
#include <toml++/toml.h>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <thread>
#include <vector>

namespace lockbox {

    namespace {
        constexpr size_t BIP448_SIGNING_ID_HEX_SIZE = 64;
        constexpr size_t BIP448_SESSION_SIZE = 133;
        constexpr size_t BIP448_SESSION_CHALLENGE_OFFSET = 4 + 1 + 32 + 32;
        constexpr size_t BIP448_SESSION_CHALLENGE_SIZE = 32;
        constexpr unsigned char MUSIG_SESSION_MAGIC[4] = {0x9d, 0xed, 0xe9, 0x17};

        std::string strip_hex_prefix(std::string value) {
            if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
                value = value.substr(2);
            }

            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });

            return value;
        }

        bool is_hex_string(const std::string& value) {
            return std::all_of(value.begin(), value.end(), [](unsigned char c) {
                return std::isxdigit(c) != 0;
            });
        }

        bool canonical_signing_id(std::string& signing_id) {
            signing_id = strip_hex_prefix(signing_id);
            return signing_id.size() == BIP448_SIGNING_ID_HEX_SIZE && is_hex_string(signing_id);
        }

        bool challenge_from_bip448_session(
            const std::vector<unsigned char>& serialized_session,
            std::string& challenge) {
            if (serialized_session.size() != BIP448_SESSION_SIZE) {
                return false;
            }

            if (!std::equal(MUSIG_SESSION_MAGIC, MUSIG_SESSION_MAGIC + sizeof(MUSIG_SESSION_MAGIC), serialized_session.begin())) {
                return false;
            }

            challenge = strip_hex_prefix(utils::key_to_string(
                serialized_session.data() + BIP448_SESSION_CHALLENGE_OFFSET,
                BIP448_SESSION_CHALLENGE_SIZE));
            return true;
        }

        crow::response bip448_partial_sig_response(const std::string& partial_sig) {
            crow::json::wvalue result({{"partial_sig", partial_sig}});
            return crow::response{result};
        }

        crow::response bip448_public_nonce_response(const std::string& server_pubnonce) {
            crow::json::wvalue result({{"server_pubnonce", server_pubnonce}});
            return crow::response{result};
        }

        crow::response bip448_conflict_response(const std::string& message) {
            return crow::response(409, message);
        }

        crow::response bip448_nonce_not_found_response() {
            return crow::response(404, "BIP448 nonce state not found for signing_id");
        }
    } // namespace

    crow::response generate_new_keypair(const std::string& statechain_id,  unsigned char *seed) {
        auto new_key_pair_response = enclave::generate_new_keypair(seed);

        std::string error_message;
        bool data_saved = db_manager::save_generated_public_key(
            new_key_pair_response.encrypted_data, 
            new_key_pair_response.server_pubkey, 
            sizeof(new_key_pair_response.server_pubkey), 
            statechain_id, 
            error_message);

        if (!data_saved) {
            error_message = "Failed to save aggregated key data: " + error_message;
            return crow::response(500, error_message);
        }

        std::string server_pubkey_hex = utils::key_to_string(new_key_pair_response.server_pubkey, 33);

        crow::json::wvalue result({{"server_pubkey", server_pubkey_hex}});
        return crow::response{result};
    }

    crow::response generate_bip448_public_nonce(
        const std::string& statechain_id,
        const std::string& signing_id,
        unsigned char *seed) {

        bool found = false;
        std::string existing_public_nonce;
        std::string error_message;
        if (!db_manager::get_bip448_public_nonce(
            statechain_id,
            signing_id,
            found,
            existing_public_nonce,
            error_message)) {
            return crow::response(500, "Failed to load BIP448 nonce state: " + error_message);
        }

        if (found) {
            return bip448_public_nonce_response(existing_public_nonce);
        }

        auto encrypted_keypair = std::make_unique<utils::chacha20_poly1305_encrypted_data>();
        bool data_loaded = db_manager::load_generated_keypair(
            statechain_id,
            encrypted_keypair,
            error_message
        );

        if (!data_loaded) {
            error_message = "Failed to load aggregated key data: " + error_message;
            return crow::response(500, error_message);
        }

        if (encrypted_keypair == nullptr) {
            return crow::response(400, "Empty encrypted keypair!");
        }

        auto response = enclave::generate_nonce(seed, encrypted_keypair.get());

        bool inserted = false;
        bool data_saved = db_manager::insert_bip448_nonce_state(
            statechain_id,
            signing_id,
            response.server_pubnonce, sizeof(response.server_pubnonce),
            response.encrypted_secnonce,
            inserted,
            error_message
        );

        if (!data_saved) {
            return crow::response(500, "Failed to save BIP448 nonce state: " + error_message);
        }

        if (!inserted) {
            if (!db_manager::get_bip448_public_nonce(
                statechain_id,
                signing_id,
                found,
                existing_public_nonce,
                error_message)) {
                return crow::response(500, "Failed to reload BIP448 nonce state: " + error_message);
            }

            if (found) {
                return bip448_public_nonce_response(existing_public_nonce);
            }

            return crow::response(500, "BIP448 nonce state was concurrently created but could not be reloaded");
        }

        auto serialized_server_pubnonce_hex = strip_hex_prefix(utils::key_to_string(response.server_pubnonce, sizeof(response.server_pubnonce)));
        return bip448_public_nonce_response(serialized_server_pubnonce_hex);
    }

    crow::response generate_bip448_partial_signature(
        const std::string& statechain_id,
        const std::string& signing_id,
        int64_t negate_seckey,
        std::vector<unsigned char>& serialized_session,
        const std::string& server_pub_nonce,
        unsigned char *seed) {

            if (negate_seckey != 0 && negate_seckey != 1) {
                return crow::response(400, "Invalid negate_seckey. Must be 0 or 1!");
            }

            std::string challenge;
            if (!challenge_from_bip448_session(serialized_session, challenge)) {
                return crow::response(400, "Invalid BIP448 session. Must be 133 bytes with Mercury MuSig session magic!");
            }

            const std::string requested_public_nonce = strip_hex_prefix(server_pub_nonce);
            std::string error_message;
            bool found = false;
            db_manager::Bip448NonceState nonce_state;
            if (!db_manager::load_bip448_nonce_state(
                statechain_id,
                signing_id,
                found,
                nonce_state,
                error_message)) {
                return crow::response(500, "Failed to load BIP448 nonce state: " + error_message);
            }

            if (!found) {
                return bip448_nonce_not_found_response();
            }

            if (nonce_state.public_nonce_hex != requested_public_nonce) {
                return bip448_conflict_response("server public nonce does not match BIP448 nonce state");
            }

            if (nonce_state.challenge.has_value()) {
                if (nonce_state.challenge.value() != challenge) {
                    return bip448_conflict_response("challenge does not match BIP448 nonce state");
                }

                if (!nonce_state.negate_seckey.has_value() || nonce_state.negate_seckey.value() != negate_seckey) {
                    return bip448_conflict_response("negate_seckey does not match BIP448 nonce state");
                }

                if (nonce_state.partial_sig.has_value()) {
                    return bip448_partial_sig_response(nonce_state.partial_sig.value());
                }
            } else {
                bool claimed = false;
                if (!db_manager::claim_bip448_nonce_challenge(
                    statechain_id,
                    signing_id,
                    challenge,
                    static_cast<int>(negate_seckey),
                    claimed,
                    error_message)) {
                    return crow::response(500, "Failed to claim BIP448 nonce challenge: " + error_message);
                }

                if (!claimed) {
                    if (!db_manager::load_bip448_nonce_state(
                        statechain_id,
                        signing_id,
                        found,
                        nonce_state,
                        error_message)) {
                        return crow::response(500, "Failed to reload BIP448 nonce state: " + error_message);
                    }

                    if (!found) {
                        return bip448_nonce_not_found_response();
                    }

                    if (!nonce_state.challenge.has_value() || nonce_state.challenge.value() != challenge) {
                        return bip448_conflict_response("challenge does not match BIP448 nonce state");
                    }

                    if (!nonce_state.negate_seckey.has_value() || nonce_state.negate_seckey.value() != negate_seckey) {
                        return bip448_conflict_response("negate_seckey does not match BIP448 nonce state");
                    }

                    if (nonce_state.partial_sig.has_value()) {
                        return bip448_partial_sig_response(nonce_state.partial_sig.value());
                    }
                }
            }

            auto encrypted_keypair = std::make_unique<utils::chacha20_poly1305_encrypted_data>();
            bool data_loaded = db_manager::load_generated_keypair(
                statechain_id,
                encrypted_keypair,
                error_message
            );

            if (!data_loaded) {
                error_message = "Failed to load aggregated key data: " + error_message;
                return crow::response(500, error_message);
            }

            if (encrypted_keypair == nullptr || nonce_state.encrypted_secnonce == nullptr) {
                return crow::response(400, "Empty sealed keypair or BIP448 sealed secnonce!");
            }

            auto response = enclave::partial_signature(
                seed,
                encrypted_keypair.get(),
                nonce_state.encrypted_secnonce.get(),
                static_cast<int>(negate_seckey),
                serialized_session.data(), serialized_session.size(),
                nonce_state.public_nonce.data());

            auto partial_sig_hex = utils::key_to_string(response.partial_sig_data, sizeof(response.partial_sig_data));

            bool saved = false;
            if (!db_manager::save_bip448_partial_signature(
                statechain_id,
                signing_id,
                challenge,
                static_cast<int>(negate_seckey),
                partial_sig_hex,
                saved,
                error_message)) {
                return crow::response(500, "Failed to save BIP448 partial signature: " + error_message);
            }

            if (saved) {
                return bip448_partial_sig_response(partial_sig_hex);
            }

            if (!db_manager::load_bip448_nonce_state(
                statechain_id,
                signing_id,
                found,
                nonce_state,
                error_message)) {
                return crow::response(500, "Failed to reload BIP448 partial signature: " + error_message);
            }

            if (found
                && nonce_state.challenge.has_value()
                && nonce_state.challenge.value() == challenge
                && nonce_state.negate_seckey.has_value()
                && nonce_state.negate_seckey.value() == negate_seckey
                && nonce_state.partial_sig.has_value()) {
                return bip448_partial_sig_response(nonce_state.partial_sig.value());
            }

            return crow::response(500, "BIP448 partial signature was not saved or replayable");
    }

    crow::response keyupdate(
        const std::string& statechain_id, 
        std::vector<unsigned char>& serialized_t2,
        std::vector<unsigned char>& serialized_x1,
        unsigned char *seed) {

            auto old_encrypted_keypair = std::make_unique<utils::chacha20_poly1305_encrypted_data>();
        
            std::string error_message;
            bool data_loaded = db_manager::load_generated_keypair(
                statechain_id,
                old_encrypted_keypair,
                error_message
            );

            if (!data_loaded) {
                error_message = "Failed to load aggregated key data: " + error_message;
                return crow::response(500, error_message);
            }

            if (old_encrypted_keypair == nullptr) {
                return crow::response(400, "Empty encrypted keypair!");
            }

            auto response = enclave::key_update(
                seed, 
                old_encrypted_keypair.get(),
                serialized_x1.data(),
                serialized_t2.data());

            bool data_saved = db_manager::update_sealed_keypair(
                response.encrypted_data, 
                response.server_pubkey, sizeof(response.server_pubkey),
                statechain_id, 
                error_message);

            if (!data_saved) {
                error_message = "Failed to update aggregated key data: " + error_message;
                return crow::response(500, error_message);
            }

            auto new_server_seckey_hex = utils::key_to_string(response.server_pubkey, sizeof(response.server_pubkey));

            crow::json::wvalue result({{"server_pubkey", new_server_seckey_hex}});
            return crow::response{result};
    }

    std::string getKeyManager() {
        return utils::getStringConfigVar(utils::KEY_MANAGER);
    }

    /**
     * Get the seed from the Hashicorp container key manager
     * This requires the container to be running
     * So this function is necessary to wait the container to be ready
     */
    std::vector<uint8_t> getHashicorpContainerSeed() {
        const auto start_time = std::chrono::steady_clock::now();
        const auto timeout_duration = std::chrono::minutes(3);
        
        while (true) {
            try {
                return hashicorp_container_key_manager::get_seed();
            } catch (const std::runtime_error& e) {
                auto current_time = std::chrono::steady_clock::now();
                if (current_time - start_time >= timeout_duration) {
                    throw std::runtime_error("Failed to get Hashicorp container seed after 3 minutes of retries");
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }

    void initializeDatabase() {
        const auto start_time = std::chrono::steady_clock::now();
        const auto timeout_duration = std::chrono::minutes(3);
        std::string error_message;

        while (true) {
            error_message.clear();
            if (db_manager::initialize_database(error_message)) {
                return;
            }

            auto current_time = std::chrono::steady_clock::now();
            if (current_time - start_time >= timeout_duration) {
                throw std::runtime_error("Failed to initialize lockbox database after 3 minutes of retries: " + error_message);
            }

            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    void start_server() {

        std::vector<uint8_t> seed;

        auto key_provider = getKeyManager();

        if (key_provider == "filesystem") {

            std::cout << "Using filesystem key manager" << std::endl;

            seed = filesystem_key_manager::get_seed();
        } else if (key_provider == "google_kms") {

            std::cout << "Using Google KMS key manager" << std::endl;

            seed = key_manager::get_seed();
        } else if (key_provider == "hashicorp_api") {

            std::cout << "Using Hashicorp API key manager" << std::endl;

            seed = hashicorp_api_key_manager::get_seed();
        } else if (key_provider == "hashicorp_container") {

            std::cout << "Using Hashicorp container key manager" << std::endl;

            seed = getHashicorpContainerSeed();
        } else {
            throw std::runtime_error("Invalid key manager: " + key_provider);
        }

        /* std::string seed_hex = utils::key_to_string(seed.data(), seed.size());

        std::cout << "Seed:       " << seed_hex << std::endl; */

        initializeDatabase();

        // Initialize Crow HTTP server
        crow::SimpleApp app;

        // Define a simple route
        CROW_ROUTE(app, "/")([](){
            return "Hello, Crow!";
        });

        CROW_ROUTE(app, "/get_public_key")
        .methods("POST"_method)([&seed](const crow::request& req) {

            auto req_body = crow::json::load(req.body);
            if (!req_body)
                return crow::response(400);

            if (req_body.count("statechain_id") == 0)
                return crow::response(400, "Invalid parameter. It must be 'statechain_id'.");

            std::string statechain_id = req_body["statechain_id"].s();

            return generate_new_keypair(statechain_id, seed.data());
        });

        CROW_ROUTE(app, "/bip448/get_public_nonce")
        .methods("POST"_method)([&seed](const crow::request& req) {

            auto req_body = crow::json::load(req.body);
            if (!req_body)
                return crow::response(400);

            if (req_body.count("statechain_id") == 0 || req_body.count("signing_id") == 0) {
                return crow::response(400, "Invalid parameters. They must be 'statechain_id' and 'signing_id'.");
            }

            std::string statechain_id = req_body["statechain_id"].s();
            std::string signing_id = req_body["signing_id"].s();

            if (!canonical_signing_id(signing_id)) {
                return crow::response(400, "Invalid signing_id. Must be a 32-byte hex string!");
            }

            return generate_bip448_public_nonce(statechain_id, signing_id, seed.data());
        });

        CROW_ROUTE(app, "/bip448/get_partial_signature")
            .methods("POST"_method)([&seed](const crow::request& req) {

                auto req_body = crow::json::load(req.body);
                if (!req_body)
                    return crow::response(400);

                if (req_body.count("statechain_id") == 0 ||
                    req_body.count("signing_id") == 0 ||
                    req_body.count("negate_seckey") == 0 ||
                    req_body.count("session") == 0 ||
                    req_body.count("server_pub_nonce") == 0) {
                    return crow::response(400, "Invalid parameters. They must be 'statechain_id', 'signing_id', 'negate_seckey', 'session' and 'server_pub_nonce'.");
                }

                std::string statechain_id = req_body["statechain_id"].s();
                std::string signing_id = req_body["signing_id"].s();
                int64_t negate_seckey = req_body["negate_seckey"].i();
                std::string session_hex = req_body["session"].s();
                std::string server_pub_nonce = req_body["server_pub_nonce"].s();

                if (!canonical_signing_id(signing_id)) {
                    return crow::response(400, "Invalid signing_id. Must be a 32-byte hex string!");
                }

                session_hex = strip_hex_prefix(session_hex);

                std::vector<unsigned char> serialized_session = utils::ParseHex(session_hex);

                if (serialized_session.size() != 133) {
                    return crow::response(400, "Invalid session length. Must be 133 bytes!");
                }

                return generate_bip448_partial_signature(
                    statechain_id,
                    signing_id,
                    negate_seckey,
                    serialized_session,
                    server_pub_nonce,
                    seed.data());

        });

        CROW_ROUTE(app,"/signature_count/<string>")
        ([](std::string statechain_id){

            int sig_count = 0;
            std::string error_message;
            bool count_retrieved = db_manager::signature_count(statechain_id, sig_count, error_message);

            if (!count_retrieved) {
                if (error_message == "Signature count not found.") {
                    return crow::response(404, error_message);
                }
                error_message = "Failed to retrieve signature count: " + error_message;
                return crow::response(500, error_message);
            }

            crow::json::wvalue result({{"sig_count", sig_count}});
            return crow::response{result};
        });

        CROW_ROUTE(app, "/keyupdate")
            .methods("POST"_method)([&seed](const crow::request& req) {
                
                auto req_body = crow::json::load(req.body);
                if (!req_body)
                    return crow::response(400);

                if (req_body.count("statechain_id") == 0 || 
                    req_body.count("t2") == 0 ||
                    req_body.count("x1") == 0) {
                    return crow::response(400, "Invalid parameters. They must be 'statechain_id', 't2' and 'x1'.");
                }

                std::string statechain_id = req_body["statechain_id"].s();
                std::string t2_hex = req_body["t2"].s();
                std::string x1_hex = req_body["x1"].s();

                if (t2_hex.substr(0, 2) == "0x") {
                    t2_hex = t2_hex.substr(2);
                }

                std::vector<unsigned char> serialized_t2 = utils::ParseHex(t2_hex);

                if (serialized_t2.size() != 32) {
                    return crow::response(400, "Invalid t2 length. Must be 32 bytes!");
                }

                if (x1_hex.substr(0, 2) == "0x") {
                    x1_hex = x1_hex.substr(2);
                }

                std::vector<unsigned char> serialized_x1 = utils::ParseHex(x1_hex);

                if (serialized_x1.size() != 32) {
                    return crow::response(400, "Invalid x1 length. Must be 32 bytes!");
                }

                return keyupdate(statechain_id, serialized_t2, serialized_x1, seed.data());
        });

        CROW_ROUTE(app,"/delete_statechain/<string>")
            .methods("DELETE"_method)([](std::string statechain_id){
                if (db_manager::delete_statechain(statechain_id)) {
                    return crow::response(200, "Statechain deleted.");
                } else {
                    return crow::response(500, "Failed to connect to the database and delete statechain.");
                }
        });

        uint16_t server_port = 0;

        try {
            server_port = utils::getServerPort();
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to get enclave port");
        }
        
        app.port(server_port).multithreaded().run();
    }
} // namespace lockbox
