#pragma once

#ifndef DB_MANAGER_H
#define DB_MANAGER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "utils.h"

namespace db_manager {

constexpr std::size_t BIP448_SCALAR_SIZE = 32;
constexpr std::size_t BIP448_PUBLIC_KEY_SIZE = 33;
constexpr std::size_t BIP448_PUBLIC_NONCE_SIZE = 66;

using Bip448Scalar = std::array<unsigned char, BIP448_SCALAR_SIZE>;
using Bip448PublicKey = std::array<unsigned char, BIP448_PUBLIC_KEY_SIZE>;
using Bip448PublicNonce = std::array<unsigned char, BIP448_PUBLIC_NONCE_SIZE>;

struct GeneratedKeyMaterial {
    utils::chacha20_poly1305_encrypted_data encrypted_keypair{};
    Bip448PublicKey server_pubkey{};
    std::uint64_t key_generation_us{0};
};

using GeneratedKeyFactory = std::function<GeneratedKeyMaterial()>;

enum class GeneratedKeyOutcome {
    Created,
    Existing,
    InvalidInput,
    StorageFailure,
};

struct GeneratedKeyTimings {
    std::uint64_t open_us{0};
    std::uint64_t transaction_us{0};
    std::uint64_t read_us{0};
    std::uint64_t insert_us{0};
    std::uint64_t commit_us{0};
};

struct GeneratedKeyResult {
    GeneratedKeyOutcome outcome{GeneratedKeyOutcome::StorageFailure};
    Bip448PublicKey server_pubkey{};
    GeneratedKeyTimings timings;
    std::uint64_t key_generation_us{0};
    std::string failure_phase;
};

enum class Bip448Outcome {
    Applied,
    ExactReplay,
    NotFound,
    InvalidInput,
    SignatureCountMismatch,
    KeyGenerationMismatch,
    ServerKeyMismatch,
    OperationConflict,
    KeyupdateRejected,
    Overflow,
    StorageFailure,
};

struct Bip448State {
    std::string statechain_id;
    std::int64_t sig_count{0};
    std::int64_t key_generation{0};
    Bip448PublicKey server_pubkey{};
};

struct Bip448Receipt {
    std::string operation_id;
    std::string statechain_id;
    std::int64_t accepted_sig_count{0};
    std::int64_t previous_key_generation{0};
    std::int64_t resulting_key_generation{0};
    Bip448PublicKey previous_server_pubkey{};
    Bip448PublicKey resulting_server_pubkey{};
    Bip448PublicKey transfer_generation_pubkey{};
};

struct Bip448Result {
    Bip448Outcome outcome{Bip448Outcome::StorageFailure};
    std::optional<Bip448State> state;
    std::optional<Bip448Receipt> receipt;
    std::string value;
    std::int64_t actual_sig_count{-1};
    std::int64_t actual_key_generation{-1};
};

struct Bip448SignFirstRequest {
    std::string statechain_id;
    std::string signing_id;
    std::int64_t expected_key_generation{0};
    Bip448PublicKey expected_server_pubkey{};
};

struct Bip448SignSecondRequest {
    std::string statechain_id;
    std::string signing_id;
    int negate_seckey{0};
    std::vector<unsigned char> session;
    Bip448PublicNonce server_pubnonce{};
    std::int64_t expected_key_generation{0};
    Bip448PublicKey expected_server_pubkey{};
};

struct Bip448KeyupdateRequest {
    std::string operation_id;
    std::string statechain_id;
    Bip448Scalar t2{};
    Bip448Scalar x1{};
    std::int64_t expected_sig_count{0};
    std::int64_t expected_key_generation{0};
    Bip448PublicKey expected_server_pubkey{};
};

bool initialize_database(
    std::string& error_message,
    const unsigned char* seed,
    std::size_t seed_size,
    bool allow_initialization);
bool database_is_ready(std::string& error_message);

GeneratedKeyResult get_or_create_generated_public_key(
    const std::string& statechain_id,
    const GeneratedKeyFactory& generate_key);

bool get_statechain_public_key(
    const std::string& statechain_id,
    bool& found,
    unsigned char* server_public_key,
    std::size_t server_public_key_size,
    std::string& error_message);

Bip448Result observe_bip448_state(const std::string& statechain_id);
Bip448Result execute_bip448_sign_first(
    const Bip448SignFirstRequest& request, unsigned char* seed);
Bip448Result execute_bip448_sign_second(
    const Bip448SignSecondRequest& request, unsigned char* seed);
Bip448Result execute_bip448_keyupdate(
    const Bip448KeyupdateRequest& request, unsigned char* seed);
Bip448Result delete_statechain(const std::string& statechain_id);

bool valid_statechain_id(const std::string& statechain_id) noexcept;

} // namespace db_manager

#endif // DB_MANAGER_H
