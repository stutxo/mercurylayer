#include "server.h"
#include <crow.h>
#include <secp256k1.h>
#include <secp256k1_musig.h>
#include "utils.h"
#include "enclave.h"
#ifdef LOCKBOX_ENABLE_GOOGLE_KMS
#include "google_key_manager.h"
#endif
#include "hashicorp_api_key_manager.h"
#include "hashicorp_container_key_manager.h"
#include "filesystem_key_manager.h"
#include "db_manager.h"
#include "request_auth.h"
#include <toml++/toml.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace lockbox {

    namespace {
    constexpr std::size_t SESSION_SIZE = 133;
    constexpr unsigned char SESSION_MAGIC[] = {0x9d, 0xed, 0xe9, 0x17};
    constexpr unsigned char GROUP_ORDER[32] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
    const std::vector<std::string> SIGN_FIRST_KEYS = {
        "expected_key_generation", "expected_server_pubkey", "signing_id", "statechain_id"};
    const std::vector<std::string> SIGN_SECOND_KEYS = {
        "expected_key_generation", "expected_server_pubkey", "negate_seckey", "server_pub_nonce",
        "session", "signing_id", "statechain_id"};
    const std::vector<std::string> KEYUPDATE_KEYS = {
        "expected_key_generation", "expected_server_pubkey", "expected_sig_count", "operation_id",
        "protocol_version", "statechain_id", "t2", "x1"};
    const std::vector<std::string> VERIFY_KEYS = {"challenge", "statechain_id"};

    using SecpPtr = std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>;
    crow::response unauthorized_response() {
        crow::response response(401, R"({"message":"Unauthorized"})");
        response.set_header("Content-Type", "application/json");
        response.set_header("WWW-Authenticate", "Bearer");
        return response;
    }

    struct EncryptedBufferGuard {
        utils::chacha20_poly1305_encrypted_data& value;
        ~EncryptedBufferGuard() { delete[] value.data; value.data = nullptr; }
    };

    std::string lower_hex(const unsigned char* data, std::size_t size) {
        constexpr char digits[] = "0123456789abcdef";
        std::string output(size * 2, '0');
        for (std::size_t i = 0; i < size; ++i) {
            output[i * 2] = digits[data[i] >> 4];
            output[i * 2 + 1] = digits[data[i] & 0x0f];
        }
        return output;
    }

    bool canonical_hex(const std::string& value, std::size_t size) {
        return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
    }

    template <std::size_t N>
    bool decode_hex(const std::string& value, std::array<unsigned char, N>& output) {
        if (!canonical_hex(value, N * 2)) return false;
        auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        for (std::size_t i = 0; i < N; ++i) {
            output[i] = static_cast<unsigned char>((digit(value[i * 2]) << 4) | digit(value[i * 2 + 1]));
        }
        return true;
    }

    bool canonical_public_key(const db_manager::Bip448PublicKey& key) {
        SecpPtr context(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), secp256k1_context_destroy);
        secp256k1_pubkey parsed;
        db_manager::Bip448PublicKey serialized{};
        std::size_t size = serialized.size();
        return context && secp256k1_ec_pubkey_parse(context.get(), &parsed, key.data(), key.size())
            && secp256k1_ec_pubkey_serialize(context.get(), serialized.data(), &size, &parsed, SECP256K1_EC_COMPRESSED)
            && size == key.size() && serialized == key;
    }

    bool canonical_public_nonce(const db_manager::Bip448PublicNonce& nonce) {
        SecpPtr context(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), secp256k1_context_destroy);
        secp256k1_musig_pubnonce parsed;
        db_manager::Bip448PublicNonce serialized{};
        return context && secp256k1_musig_pubnonce_parse(context.get(), &parsed, nonce.data())
            && secp256k1_musig_pubnonce_serialize(context.get(), serialized.data(), &parsed)
            && serialized == nonce;
    }

    bool canonical_session(const std::vector<unsigned char>& session) {
        if (session.size() != SESSION_SIZE || !std::equal(std::begin(SESSION_MAGIC), std::end(SESSION_MAGIC), session.begin())
            || (session[4] != 0 && session[4] != 1)
            || std::any_of(session.begin() + 5, session.begin() + 37, [](unsigned char c) { return c != 0; })) return false;
        for (std::size_t offset : {37u, 69u, 101u}) {
            if (!std::lexicographical_compare(session.begin() + offset, session.begin() + offset + 32,
                    std::begin(GROUP_ORDER), std::end(GROUP_ORDER))) return false;
        }
        return true;
    }

    bool exact_object(const crow::json::rvalue& body, const std::vector<std::string>& expected) {
        try {
            if (body.t() != crow::json::type::Object) return false;
            auto keys = body.keys();
            std::sort(keys.begin(), keys.end());
            return keys == expected;
        } catch (const std::exception&) { return false; }
    }

    bool read_string(const crow::json::rvalue& body, const char* key, std::string& value) {
        try {
            if (body[key].t() != crow::json::type::String) return false;
            value = static_cast<std::string>(body[key].s());
            return true;
        } catch (const std::exception&) { return false; }
    }

    bool read_u64(const crow::json::rvalue& body, const char* key, std::uint64_t& value) {
        try {
            if (body[key].t() != crow::json::type::Number
                || body[key].nt() != crow::json::num_type::Unsigned_integer) return false;
            value = body[key].u();
            return true;
        } catch (const std::exception&) { return false; }
    }

    bool read_counter(const crow::json::rvalue& body, const char* key, std::int64_t& value) {
        std::uint64_t wire = 0;
        if (!read_u64(body, key, wire) || wire > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return false;
        value = static_cast<std::int64_t>(wire);
        return true;
    }

    bool read_statechain_id(const crow::json::rvalue& body, std::string& value) {
        return read_string(body, "statechain_id", value) && db_manager::valid_statechain_id(value);
    }

    bool read_public_key(const crow::json::rvalue& body, db_manager::Bip448PublicKey& value) {
        std::string encoded;
        return read_string(body, "expected_server_pubkey", encoded) && decode_hex(encoded, value)
            && canonical_public_key(value);
    }

    bool read_scalar(const crow::json::rvalue& body, const char* key, db_manager::Bip448Scalar& value) {
        std::string encoded;
        SecpPtr context(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), secp256k1_context_destroy);
        return read_string(body, key, encoded) && decode_hex(encoded, value) && context
            && secp256k1_ec_seckey_verify(context.get(), value.data());
    }

    bool parse_sign_first(const crow::json::rvalue& body, db_manager::Bip448SignFirstRequest& request) {
        return exact_object(body, SIGN_FIRST_KEYS) && read_statechain_id(body, request.statechain_id)
            && read_string(body, "signing_id", request.signing_id) && canonical_hex(request.signing_id, 64)
            && read_counter(body, "expected_key_generation", request.expected_key_generation)
            && read_public_key(body, request.expected_server_pubkey);
    }

    bool parse_sign_second(const crow::json::rvalue& body, db_manager::Bip448SignSecondRequest& request) {
        std::string session, nonce;
        std::uint64_t negate = 0;
        return exact_object(body, SIGN_SECOND_KEYS) && read_statechain_id(body, request.statechain_id)
            && read_string(body, "signing_id", request.signing_id) && canonical_hex(request.signing_id, 64)
            && read_u64(body, "negate_seckey", negate) && negate <= 1
            && read_string(body, "session", session) && canonical_hex(session, SESSION_SIZE * 2)
            && (request.session = utils::ParseHex(session), canonical_session(request.session))
            && read_string(body, "server_pub_nonce", nonce) && decode_hex(nonce, request.server_pubnonce)
            && canonical_public_nonce(request.server_pubnonce)
            && read_counter(body, "expected_key_generation", request.expected_key_generation)
            && read_public_key(body, request.expected_server_pubkey)
            && (request.negate_seckey = static_cast<int>(negate), true);
    }

    bool parse_keyupdate(const crow::json::rvalue& body, db_manager::Bip448KeyupdateRequest& request) {
        std::uint64_t version = 0;
        return exact_object(body, KEYUPDATE_KEYS) && read_u64(body, "protocol_version", version) && version == 2
            && read_string(body, "operation_id", request.operation_id) && canonical_hex(request.operation_id, 64)
            && read_statechain_id(body, request.statechain_id) && read_scalar(body, "t2", request.t2)
            && read_scalar(body, "x1", request.x1)
            && read_counter(body, "expected_sig_count", request.expected_sig_count)
            && read_counter(body, "expected_key_generation", request.expected_key_generation)
            && read_public_key(body, request.expected_server_pubkey);
    }

    crow::response json_response(int status, crow::json::wvalue body) {
        crow::response response(status, body.dump());
        response.set_header("Content-Type", "application/json");
        return response;
    }

    crow::response result_error(
        const db_manager::Bip448Result& result, const std::string* operation_id = nullptr,
        const std::int64_t* expected_count = nullptr, const std::int64_t* expected_generation = nullptr) {
        if (result.outcome == db_manager::Bip448Outcome::InvalidInput) return crow::response(400, "Invalid BIP448 request");
        if (result.outcome == db_manager::Bip448Outcome::NotFound) return crow::response(404, "BIP448 state not found");
        const char* code = nullptr;
        switch (result.outcome) {
        case db_manager::Bip448Outcome::SignatureCountMismatch: code = "bip448_signature_count_mismatch"; break;
        case db_manager::Bip448Outcome::KeyGenerationMismatch: code = "bip448_key_generation_mismatch"; break;
        case db_manager::Bip448Outcome::ServerKeyMismatch: code = "bip448_server_key_mismatch"; break;
        case db_manager::Bip448Outcome::OperationConflict: code = "bip448_operation_conflict"; break;
        case db_manager::Bip448Outcome::Overflow:
        case db_manager::Bip448Outcome::KeyupdateRejected: code = "bip448_keyupdate_rejected"; break;
        default: return crow::response(500, "BIP448 storage operation failed");
        }
        crow::json::wvalue body;
        body["code"] = code; body["message"] = "BIP448 request conflicts with current state";
        if (operation_id) body["operation_id"] = *operation_id;
        if (expected_count) body["expected_sig_count"] = static_cast<std::uint64_t>(*expected_count);
        if (result.actual_sig_count >= 0 && expected_count) body["actual_sig_count"] = static_cast<std::uint64_t>(result.actual_sig_count);
        if (expected_generation) body["expected_key_generation"] = static_cast<std::uint64_t>(*expected_generation);
        if (result.actual_key_generation >= 0 && expected_generation) body["actual_key_generation"] = static_cast<std::uint64_t>(result.actual_key_generation);
        return json_response(409, std::move(body));
    }
    } // namespace

    crow::response generate_new_keypair(const std::string& statechain_id, unsigned char* seed) {
        if (!db_manager::valid_statechain_id(statechain_id)) return crow::response(400);
        try {
            auto generated = enclave::generate_new_keypair(seed);
            EncryptedBufferGuard guard{generated.encrypted_data};
            std::string error;
            if (!db_manager::save_generated_public_key(generated.encrypted_data, generated.server_pubkey,
                    sizeof(generated.server_pubkey), statechain_id, error)) return crow::response(500, "Failed to store key");
            crow::json::wvalue body; body["server_pubkey"] = lower_hex(generated.server_pubkey, sizeof(generated.server_pubkey));
            return json_response(200, std::move(body));
        } catch (const std::exception&) { return crow::response(500, "Failed to generate key"); }
    }

    crow::response verify_statechain(
        const std::string& statechain_id,
        const std::string& challenge
    ) {
        bool found = false;
        db_manager::Bip448PublicKey server_public_key{};
        std::string error_message;
        if (!db_manager::get_statechain_public_key(
                statechain_id,
                found,
                server_public_key.data(),
                server_public_key.size(),
                error_message)) {
            return crow::response(500, "Failed to verify statechain: " + error_message);
        }
        if (!found) return crow::response(404, "Statechain not found.");

        crow::json::wvalue body;
        body["statechain_id"] = statechain_id;
        body["challenge"] = challenge;
        body["server_pubkey"] =
            lower_hex(server_public_key.data(), server_public_key.size());
        return json_response(200, std::move(body));
    }

    crow::response generate_bip448_public_nonce(const db_manager::Bip448SignFirstRequest& request, unsigned char* seed) {
        const auto result = db_manager::execute_bip448_sign_first(request, seed);
        if (result.outcome != db_manager::Bip448Outcome::Applied && result.outcome != db_manager::Bip448Outcome::ExactReplay) {
            return result_error(result, nullptr, nullptr, &request.expected_key_generation);
        }
        crow::json::wvalue body; body["server_pubnonce"] = result.value;
        return json_response(200, std::move(body));
    }

    crow::response generate_bip448_partial_signature(const db_manager::Bip448SignSecondRequest& request, unsigned char* seed) {
        const auto result = db_manager::execute_bip448_sign_second(request, seed);
        if (result.outcome != db_manager::Bip448Outcome::Applied && result.outcome != db_manager::Bip448Outcome::ExactReplay) {
            return result_error(result, nullptr, nullptr, &request.expected_key_generation);
        }
        crow::json::wvalue body; body["partial_sig"] = result.value;
        return json_response(200, std::move(body));
    }

    crow::response keyupdate(const db_manager::Bip448KeyupdateRequest& request, unsigned char* seed) {
        const auto result = db_manager::execute_bip448_keyupdate(request, seed);
        if (result.outcome != db_manager::Bip448Outcome::Applied && result.outcome != db_manager::Bip448Outcome::ExactReplay) {
            return result_error(result, &request.operation_id, &request.expected_sig_count, &request.expected_key_generation);
        }
        if (!result.receipt) return crow::response(500, "BIP448 receipt missing");
        const auto& receipt = *result.receipt;
        crow::json::wvalue body;
        body["protocol_version"] = 2; body["operation_id"] = receipt.operation_id;
        body["statechain_id"] = receipt.statechain_id; body["status"] = "applied";
        body["accepted_sig_count"] = static_cast<std::uint64_t>(receipt.accepted_sig_count);
        body["previous_key_generation"] = static_cast<std::uint64_t>(receipt.previous_key_generation);
        body["resulting_key_generation"] = static_cast<std::uint64_t>(receipt.resulting_key_generation);
        body["previous_server_pubkey"] = lower_hex(receipt.previous_server_pubkey.data(), receipt.previous_server_pubkey.size());
        body["resulting_server_pubkey"] = lower_hex(receipt.resulting_server_pubkey.data(), receipt.resulting_server_pubkey.size());
        body["transfer_generation_pubkey"] = lower_hex(receipt.transfer_generation_pubkey.data(), receipt.transfer_generation_pubkey.size());
        return json_response(200, std::move(body));
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

    void initializeDatabase(
        const std::vector<uint8_t>& seed,
        bool allow_initialization
    ) {
        const auto start_time = std::chrono::steady_clock::now();
        const auto timeout_duration = std::chrono::minutes(3);
        std::string error_message;

        while (true) {
            error_message.clear();
            if (db_manager::initialize_database(
                    error_message,
                    seed.data(),
                    seed.size(),
                    allow_initialization)) {
                return;
            }

#ifdef LOCKBOX_DATABASE_BACKEND_SQLITE
            throw std::runtime_error(error_message);
#else
            if (error_message == "incompatible legacy lockbox database") {
                throw std::runtime_error(error_message);
            }
            if (std::chrono::steady_clock::now() - start_time >= timeout_duration) {
                throw std::runtime_error(
                    "Failed to initialize lockbox database after 3 minutes of retries: " +
                    error_message
                );
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
#endif
        }
    }

    void start_server() {
        const auto key_provider = getKeyManager();
        const auto authenticator = request_auth::Authenticator::from_environment();
        std::cout << "[lockbox] request authentication="
                  << (authenticator.enabled() ? "required" : "disabled") << std::endl;

        bool allow_database_initialization = true;
#ifdef LOCKBOX_DATABASE_BACKEND_SQLITE
        if (key_provider != "filesystem") {
            throw std::runtime_error("The SQLite backend requires the filesystem key manager.");
        }
        allow_database_initialization =
            filesystem_key_manager::embedded_storage_needs_initialization();
#endif

        std::vector<uint8_t> seed;
        if (key_provider == "filesystem") {
            std::cout << "Using filesystem key manager" << std::endl;
            seed = filesystem_key_manager::get_seed();
        } else if (key_provider == "google_kms") {
#ifdef LOCKBOX_ENABLE_GOOGLE_KMS
            std::cout << "Using Google KMS key manager" << std::endl;
            seed = key_manager::get_seed();
#else
            throw std::runtime_error(
                "Google KMS key manager was not built. "
                "Rebuild with -DLOCKBOX_ENABLE_GOOGLE_KMS=ON."
            );
#endif
        } else if (key_provider == "hashicorp_api") {
            std::cout << "Using Hashicorp API key manager" << std::endl;
            seed = hashicorp_api_key_manager::get_seed();
        } else if (key_provider == "hashicorp_container") {
            std::cout << "Using Hashicorp container key manager" << std::endl;
            seed = getHashicorpContainerSeed();
        } else {
            throw std::runtime_error("Invalid key manager: " + key_provider);
        }

        initializeDatabase(seed, allow_database_initialization);

        crow::SimpleApp app;
        // Define a simple route
        CROW_ROUTE(app, "/")([&authenticator](const crow::request& req) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            return crow::response(200, "Hello, Crow!");
        });

        CROW_ROUTE(app, "/health/ready")([&authenticator](const crow::request& req) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            std::string error_message;
            if (!db_manager::database_is_ready(error_message)) {
                return crow::response(503, "Lockbox database is not ready: " + error_message);
            }
            crow::json::wvalue body;
            body["status"] = "ready";
            return json_response(200, std::move(body));
        });

        CROW_ROUTE(app, "/get_public_key")
        .methods("POST"_method)([&seed, &authenticator](const crow::request& req) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            auto req_body = crow::json::load(req.body);
            if (!req_body) return crow::response(400);
            if (req_body.count("statechain_id") == 0)
                return crow::response(400, "Invalid parameter. It must be 'statechain_id'.");
            std::string statechain_id = req_body["statechain_id"].s();
            return generate_new_keypair(statechain_id, seed.data());
        });

        CROW_ROUTE(app, "/bip448/get_public_nonce")
        .methods("POST"_method)([&seed, &authenticator](const crow::request& req) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            auto req_body = crow::json::load(req.body);
            db_manager::Bip448SignFirstRequest request;
            if (!req_body || !parse_sign_first(req_body, request)) return crow::response(400, "Invalid BIP448 request");
            return generate_bip448_public_nonce(request, seed.data());
        });

        CROW_ROUTE(app, "/bip448/get_partial_signature")
        .methods("POST"_method)([&seed, &authenticator](const crow::request& req) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            auto req_body = crow::json::load(req.body);
            db_manager::Bip448SignSecondRequest request;
            if (!req_body || !parse_sign_second(req_body, request)) return crow::response(400, "Invalid BIP448 request");
            return generate_bip448_partial_signature(request, seed.data());
        });

        CROW_ROUTE(app,"/signature_count/<string>")
        ([&authenticator](const crow::request& req, std::string statechain_id) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            const auto result = db_manager::observe_bip448_state(statechain_id);
            if (result.outcome == db_manager::Bip448Outcome::NotFound) {
                return crow::response(404, "Signature count not found.");
            }
            if (result.outcome != db_manager::Bip448Outcome::Applied || !result.state) {
                return result_error(result);
            }
            crow::json::wvalue body;
            body["sig_count"] = static_cast<std::uint64_t>(result.state->sig_count);
            return json_response(200, std::move(body));
        });

        CROW_ROUTE(app, "/verify_statechain")
        .methods("POST"_method)([](const crow::request& req) {
            auto body = crow::json::load(req.body);
            std::string statechain_id;
            std::string challenge;
            if (!body || !exact_object(body, VERIFY_KEYS) ||
                !read_statechain_id(body, statechain_id) ||
                !read_string(body, "challenge", challenge) ||
                !canonical_hex(challenge, 64)) {
                return crow::response(
                    400,
                    "Invalid parameters. They must be a statechain_id and 32-byte hex challenge."
                );
            }
            return verify_statechain(statechain_id, challenge);
        });

        CROW_ROUTE(app,"/bip448/state/<string>")
        ([&authenticator](const crow::request& req, std::string statechain_id) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            const auto result = db_manager::observe_bip448_state(statechain_id);
            if (result.outcome != db_manager::Bip448Outcome::Applied || !result.state) {
                return result_error(result);
            }
            crow::json::wvalue body;
            body["protocol_version"] = 2;
            body["statechain_id"] = result.state->statechain_id;
            body["sig_count"] = static_cast<std::uint64_t>(result.state->sig_count);
            body["key_generation"] = static_cast<std::uint64_t>(result.state->key_generation);
            body["server_pubkey"] =
                lower_hex(result.state->server_pubkey.data(), result.state->server_pubkey.size());
            return json_response(200, std::move(body));
        });

        CROW_ROUTE(app, "/keyupdate")
        .methods("POST"_method)([&seed, &authenticator](const crow::request& req) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            auto req_body = crow::json::load(req.body);
            db_manager::Bip448KeyupdateRequest request;
            if (!req_body || !parse_keyupdate(req_body, request)) return crow::response(400, "Invalid BIP448 request");
            return keyupdate(request, seed.data());
        });

        CROW_ROUTE(app,"/delete_statechain/<string>")
        .methods("DELETE"_method)([&authenticator](
            const crow::request& req,
            std::string statechain_id
        ) {
            if (!authenticator.authorized(req.get_header_value("Authorization"))) {
                return unauthorized_response();
            }
            const auto result = db_manager::delete_statechain(statechain_id);
            if (result.outcome == db_manager::Bip448Outcome::Applied ||
                result.outcome == db_manager::Bip448Outcome::ExactReplay) {
                return crow::response(200, "Statechain deleted.");
            }
            return result_error(result);
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
