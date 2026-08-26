#include "db_manager.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <memory>
#include <pqxx/pqxx>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <secp256k1.h>

#include "enclave.h"

namespace db_manager {
namespace {

constexpr char KEYUPDATE_DOMAIN[] = "BIP448/lockbox-keyupdate/v2\0";
constexpr std::size_t MAX_SEALED_SIZE = 4096;
constexpr std::size_t SESSION_CHALLENGE_OFFSET = 69;
constexpr std::size_t SESSION_CHALLENGE_SIZE = 32;

std::string database_url() {
    return utils::getStringConfigVar(utils::DATABASE_URL);
}

std::basic_string_view<std::byte> bytes(const unsigned char* data, std::size_t size) {
    return {reinterpret_cast<const std::byte*>(data), size};
}

std::vector<unsigned char> field_bytes(const pqxx::field& field) {
    auto value = field.as<std::basic_string<std::byte>>();
    std::vector<unsigned char> result(value.size());
    std::memcpy(result.data(), value.data(), value.size());
    return result;
}

template <std::size_t N>
bool field_array(const pqxx::field& field, std::array<unsigned char, N>& output) {
    const auto value = field_bytes(field);
    if (value.size() != N) return false;
    std::copy(value.begin(), value.end(), output.begin());
    return true;
}

std::string lower_hex(const unsigned char* data, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        result[i * 2] = digits[data[i] >> 4];
        result[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    return result;
}

bool lower_hex_string(const std::string& value, std::size_t size) {
    return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

template <std::size_t N>
bool equal(const std::array<unsigned char, N>& left, const std::array<unsigned char, N>& right) {
    return CRYPTO_memcmp(left.data(), right.data(), N) == 0;
}

struct EncryptedDeleter {
    void operator()(utils::chacha20_poly1305_encrypted_data* value) const {
        if (!value) return;
        if (value->data) {
            OPENSSL_cleanse(value->data, value->data_len);
            delete[] value->data;
        }
        delete value;
    }
};
using EncryptedPtr = std::unique_ptr<utils::chacha20_poly1305_encrypted_data, EncryptedDeleter>;

struct EncryptedBufferGuard {
    utils::chacha20_poly1305_encrypted_data& value;
    ~EncryptedBufferGuard() {
        if (value.data) {
            OPENSSL_cleanse(value.data, value.data_len);
            delete[] value.data;
            value.data = nullptr;
        }
    }
};

std::vector<unsigned char> serialize_encrypted(
    const utils::chacha20_poly1305_encrypted_data& value) {
    const std::size_t header = sizeof(value.data_len) + sizeof(value.nonce) + sizeof(value.mac);
    if (!value.data || value.data_len == 0 || value.data_len > MAX_SEALED_SIZE) {
        throw std::runtime_error("invalid encrypted data");
    }
    std::vector<unsigned char> output(header + value.data_len);
    std::size_t offset = 0;
    std::memcpy(output.data() + offset, &value.data_len, sizeof(value.data_len));
    offset += sizeof(value.data_len);
    std::memcpy(output.data() + offset, value.nonce, sizeof(value.nonce));
    offset += sizeof(value.nonce);
    std::memcpy(output.data() + offset, value.mac, sizeof(value.mac));
    offset += sizeof(value.mac);
    std::memcpy(output.data() + offset, value.data, value.data_len);
    return output;
}

EncryptedPtr deserialize_encrypted(const std::vector<unsigned char>& value) {
    const std::size_t header = sizeof(std::size_t) + 24 + 16;
    if (value.size() < header) return {};
    std::size_t data_len = 0;
    std::memcpy(&data_len, value.data(), sizeof(data_len));
    if (data_len == 0 || data_len > MAX_SEALED_SIZE || value.size() != header + data_len) return {};
    EncryptedPtr result(new utils::chacha20_poly1305_encrypted_data{});
    result->data_len = data_len;
    std::size_t offset = sizeof(data_len);
    std::memcpy(result->nonce, value.data() + offset, sizeof(result->nonce));
    offset += sizeof(result->nonce);
    std::memcpy(result->mac, value.data() + offset, sizeof(result->mac));
    offset += sizeof(result->mac);
    result->data = new unsigned char[data_len];
    std::memcpy(result->data, value.data() + offset, data_len);
    return result;
}

void append_u32(std::vector<unsigned char>& output, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) output.push_back(value >> shift);
}

void append_u64(std::vector<unsigned char>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) output.push_back(value >> shift);
}

std::string sha256_hex(const std::vector<unsigned char>& value) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(value.data(), value.size(), digest.data());
    return lower_hex(digest.data(), digest.size());
}

bool decode_operation_id(const std::string& value, std::array<unsigned char, 32>& output) {
    if (!lower_hex_string(value, 64)) return false;
    auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i < output.size(); ++i) {
        output[i] = static_cast<unsigned char>((digit(value[i * 2]) << 4) | digit(value[i * 2 + 1]));
    }
    return true;
}

bool request_hash(const Bip448KeyupdateRequest& request, std::string& output) {
    std::array<unsigned char, 32> operation{};
    if (!decode_operation_id(request.operation_id, operation)
        || !valid_statechain_id(request.statechain_id)
        || request.expected_sig_count < 0 || request.expected_key_generation < 0) return false;
    std::vector<unsigned char> preimage(std::begin(KEYUPDATE_DOMAIN), std::end(KEYUPDATE_DOMAIN) - 1);
    preimage.push_back(2);
    preimage.insert(preimage.end(), operation.begin(), operation.end());
    append_u32(preimage, static_cast<std::uint32_t>(request.statechain_id.size()));
    preimage.insert(preimage.end(), request.statechain_id.begin(), request.statechain_id.end());
    preimage.insert(preimage.end(), request.t2.begin(), request.t2.end());
    preimage.insert(preimage.end(), request.x1.begin(), request.x1.end());
    append_u64(preimage, static_cast<std::uint64_t>(request.expected_sig_count));
    append_u64(preimage, static_cast<std::uint64_t>(request.expected_key_generation));
    preimage.insert(preimage.end(), request.expected_server_pubkey.begin(), request.expected_server_pubkey.end());
    output = sha256_hex(preimage);
    return true;
}

using SecpPtr = std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>;

bool keyupdate_public_keys(
    const Bip448KeyupdateRequest& request,
    const Bip448PublicKey& current,
    Bip448PublicKey& transfer,
    Bip448PublicKey& resulting) {
    SecpPtr context(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), secp256k1_context_destroy);
    if (!context || !secp256k1_ec_seckey_verify(context.get(), request.t2.data())
        || !secp256k1_ec_seckey_verify(context.get(), request.x1.data())) return false;
    secp256k1_pubkey current_key, t2_key, x1_key;
    if (!secp256k1_ec_pubkey_parse(context.get(), &current_key, current.data(), current.size())
        || !secp256k1_ec_pubkey_create(context.get(), &t2_key, request.t2.data())
        || !secp256k1_ec_pubkey_create(context.get(), &x1_key, request.x1.data())) return false;
    std::size_t size = transfer.size();
    if (!secp256k1_ec_pubkey_serialize(context.get(), transfer.data(), &size, &x1_key, SECP256K1_EC_COMPRESSED)
        || size != transfer.size()) return false;
    secp256k1_pubkey plus_t2, neg_x1 = x1_key, final_key;
    const secp256k1_pubkey* first[] = {&current_key, &t2_key};
    if (!secp256k1_ec_pubkey_combine(context.get(), &plus_t2, first, 2)
        || !secp256k1_ec_pubkey_negate(context.get(), &neg_x1)) return false;
    const secp256k1_pubkey* second[] = {&plus_t2, &neg_x1};
    if (!secp256k1_ec_pubkey_combine(context.get(), &final_key, second, 2)) return false;
    size = resulting.size();
    return secp256k1_ec_pubkey_serialize(context.get(), resulting.data(), &size, &final_key, SECP256K1_EC_COMPRESSED)
        && size == resulting.size();
}

void initialize_schema(pqxx::work& txn) {
    txn.exec(R"SQL(
        CREATE TABLE IF NOT EXISTS public.generated_public_key (
            id SERIAL PRIMARY KEY, statechain_id VARCHAR(50) NOT NULL,
            sealed_keypair BYTEA, public_key BYTEA UNIQUE,
            sig_count BIGINT NOT NULL DEFAULT 0,
            key_generation BIGINT NOT NULL DEFAULT 0);
        ALTER TABLE public.generated_public_key ADD COLUMN IF NOT EXISTS key_generation BIGINT;
    )SQL");
    const auto invalid = txn.exec(R"SQL(
        SELECT EXISTS (
            SELECT 1 FROM public.generated_public_key
            WHERE statechain_id IS NULL OR sig_count IS NULL OR sig_count < 0 OR key_generation < 0
        ) OR EXISTS (
            SELECT 1 FROM public.generated_public_key GROUP BY statechain_id HAVING COUNT(*) > 1
        ) AS invalid
    )SQL");
    if (invalid[0]["invalid"].as<bool>()) throw std::runtime_error("invalid legacy generated-key rows");
    txn.exec(R"SQL(
        UPDATE public.generated_public_key SET key_generation = 0 WHERE key_generation IS NULL;
        ALTER TABLE public.generated_public_key ALTER COLUMN statechain_id SET NOT NULL;
        ALTER TABLE public.generated_public_key ALTER COLUMN sig_count TYPE BIGINT USING sig_count::BIGINT;
        ALTER TABLE public.generated_public_key ALTER COLUMN sig_count SET DEFAULT 0;
        ALTER TABLE public.generated_public_key ALTER COLUMN sig_count SET NOT NULL;
        ALTER TABLE public.generated_public_key ALTER COLUMN key_generation SET DEFAULT 0;
        ALTER TABLE public.generated_public_key ALTER COLUMN key_generation SET NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS generated_public_key_statechain_id_key
            ON public.generated_public_key (statechain_id);
        DO $migration$ BEGIN
          BEGIN ALTER TABLE public.generated_public_key ADD CONSTRAINT generated_public_key_sig_count_nonnegative CHECK (sig_count >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END;
          BEGIN ALTER TABLE public.generated_public_key ADD CONSTRAINT generated_public_key_key_generation_nonnegative CHECK (key_generation >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END;
        END $migration$;
    )SQL");
    txn.exec(R"SQL(
        CREATE TABLE IF NOT EXISTS public.bip448_nonce_state (
            id SERIAL PRIMARY KEY, statechain_id VARCHAR(50) NOT NULL,
            signing_id VARCHAR(64) NOT NULL, key_generation BIGINT NOT NULL,
            public_nonce BYTEA NOT NULL, sealed_secnonce BYTEA NOT NULL,
            challenge VARCHAR(64), negate_seckey INTEGER, partial_sig VARCHAR,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT bip448_nonce_state_unique UNIQUE (statechain_id, signing_id),
            CONSTRAINT bip448_nonce_state_signing_id_check CHECK (signing_id ~ '^[0-9a-f]{64}$'),
            CONSTRAINT bip448_nonce_state_challenge_check CHECK (challenge IS NULL OR challenge ~ '^[0-9a-f]{64}$'),
            CONSTRAINT bip448_nonce_state_negate_check CHECK (negate_seckey IS NULL OR negate_seckey IN (0, 1)),
            CONSTRAINT bip448_nonce_state_claim_check CHECK (
              (challenge IS NULL AND negate_seckey IS NULL AND partial_sig IS NULL)
              OR (challenge IS NOT NULL AND negate_seckey IS NOT NULL)),
            CONSTRAINT bip448_nonce_state_parent FOREIGN KEY (statechain_id)
              REFERENCES public.generated_public_key(statechain_id) ON DELETE CASCADE);
        ALTER TABLE public.bip448_nonce_state ADD COLUMN IF NOT EXISTS key_generation BIGINT;
        UPDATE public.bip448_nonce_state SET key_generation = 0 WHERE key_generation IS NULL;
    )SQL");
    if (!txn.exec("SELECT 1 FROM public.bip448_nonce_state WHERE key_generation < 0 LIMIT 1").empty()) {
        throw std::runtime_error("invalid legacy nonce rows");
    }
    txn.exec(R"SQL(
        ALTER TABLE public.bip448_nonce_state ALTER COLUMN key_generation SET NOT NULL;
        DO $migration$ BEGIN
          BEGIN ALTER TABLE public.bip448_nonce_state ADD CONSTRAINT bip448_nonce_state_key_generation_nonnegative CHECK (key_generation >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END;
          BEGIN ALTER TABLE public.bip448_nonce_state ADD CONSTRAINT bip448_nonce_state_parent FOREIGN KEY (statechain_id) REFERENCES public.generated_public_key(statechain_id) ON DELETE CASCADE; EXCEPTION WHEN duplicate_object THEN NULL; END;
        END $migration$;
        CREATE TABLE IF NOT EXISTS public.bip448_keyupdate_receipt (
            statechain_id VARCHAR(50) NOT NULL, operation_id VARCHAR(64) NOT NULL,
            request_hash VARCHAR(64) NOT NULL, accepted_sig_count BIGINT NOT NULL CHECK (accepted_sig_count >= 0),
            previous_key_generation BIGINT NOT NULL CHECK (previous_key_generation >= 0),
            resulting_key_generation BIGINT NOT NULL CHECK (resulting_key_generation = previous_key_generation + 1),
            previous_server_pubkey BYTEA NOT NULL, resulting_server_pubkey BYTEA NOT NULL,
            transfer_generation_pubkey BYTEA NOT NULL, PRIMARY KEY (statechain_id, operation_id),
            FOREIGN KEY (statechain_id) REFERENCES public.generated_public_key(statechain_id) ON DELETE CASCADE);
    )SQL");
}

struct LockedParent {
    std::vector<unsigned char> sealed;
    Bip448PublicKey key{};
    std::int64_t count{0};
    std::int64_t generation{0};
};

bool lock_parent(pqxx::work& txn, const std::string& id, LockedParent& parent) {
    const auto rows = txn.exec_params(
        "SELECT sealed_keypair, public_key, sig_count, key_generation FROM public.generated_public_key WHERE statechain_id=$1 FOR UPDATE", id);
    if (rows.empty()) return false;
    if (rows.size() != 1) throw std::runtime_error("invalid parent cardinality");
    parent.sealed = field_bytes(rows[0]["sealed_keypair"]);
    parent.count = rows[0]["sig_count"].as<std::int64_t>();
    parent.generation = rows[0]["key_generation"].as<std::int64_t>();
    if (parent.sealed.empty() || parent.count < 0 || parent.generation < 0
        || !field_array(rows[0]["public_key"], parent.key)) throw std::runtime_error("invalid parent row");
    return true;
}

struct LockedNonce {
    std::int64_t id{0};
    std::int64_t generation{0};
    Bip448PublicNonce nonce{};
    std::vector<unsigned char> sealed;
    std::optional<std::string> challenge;
    std::optional<int> negate;
    std::optional<std::string> partial;
};

bool lock_nonce(pqxx::work& txn, const std::string& statechain_id, const std::string& signing_id, LockedNonce& nonce) {
    const auto rows = txn.exec_params(
        "SELECT id,key_generation,public_nonce,sealed_secnonce,challenge,negate_seckey,partial_sig FROM public.bip448_nonce_state WHERE statechain_id=$1 AND signing_id=$2 FOR UPDATE",
        statechain_id, signing_id);
    if (rows.empty()) return false;
    if (rows.size() != 1) throw std::runtime_error("invalid nonce cardinality");
    nonce.id = rows[0]["id"].as<std::int64_t>();
    nonce.generation = rows[0]["key_generation"].as<std::int64_t>();
    nonce.sealed = field_bytes(rows[0]["sealed_secnonce"]);
    if (!field_array(rows[0]["public_nonce"], nonce.nonce) || nonce.generation < 0) throw std::runtime_error("invalid nonce row");
    if (!rows[0]["challenge"].is_null()) nonce.challenge = rows[0]["challenge"].as<std::string>();
    if (!rows[0]["negate_seckey"].is_null()) nonce.negate = rows[0]["negate_seckey"].as<int>();
    if (!rows[0]["partial_sig"].is_null()) nonce.partial = rows[0]["partial_sig"].as<std::string>();
    return true;
}

bool parent_matches(const LockedParent& parent, std::int64_t generation, const Bip448PublicKey& key, Bip448Result& result) {
    result.actual_sig_count = parent.count;
    result.actual_key_generation = parent.generation;
    if (parent.generation != generation) { result.outcome = Bip448Outcome::KeyGenerationMismatch; return false; }
    if (!equal(parent.key, key)) { result.outcome = Bip448Outcome::ServerKeyMismatch; return false; }
    return true;
}

} // namespace

bool initialize_database(
    std::string& error_message,
    const unsigned char* seed,
    std::size_t seed_size,
    bool allow_initialization) {
    (void)seed;
    (void)seed_size;
    (void)allow_initialization;
    error_message.clear();
    try {
        pqxx::connection connection(database_url());
        if (!connection.is_open()) {
            error_message = "database unavailable";
            return false;
        }
        pqxx::work txn(connection);
        txn.exec("SELECT pg_advisory_xact_lock(4480002)");
        initialize_schema(txn);
        txn.commit();
        return true;
    } catch (const pqxx::broken_connection&) {
        error_message = "database unavailable";
    } catch (const std::exception&) {
        error_message = "incompatible legacy lockbox database";
    }
    return false;
}

bool database_is_ready(std::string& error_message) {
    error_message.clear();
    try {
        pqxx::connection connection(database_url());
        if (!connection.is_open()) {
            error_message = "database unavailable";
            return false;
        }
        pqxx::nontransaction txn(connection);
        txn.exec(
            "SELECT statechain_id,sealed_keypair,public_key,sig_count,key_generation "
            "FROM public.generated_public_key LIMIT 0");
        txn.exec(
            "SELECT statechain_id,signing_id,key_generation,public_nonce,sealed_secnonce,"
            "challenge,negate_seckey,partial_sig FROM public.bip448_nonce_state LIMIT 0");
        txn.exec(
            "SELECT statechain_id,operation_id,request_hash FROM "
            "public.bip448_keyupdate_receipt LIMIT 0");
        return true;
    } catch (const std::exception& error) {
        error_message = error.what();
        return false;
    }
}

bool save_generated_public_key(
    const utils::chacha20_poly1305_encrypted_data& encrypted_keypair,
    const unsigned char* server_public_key, std::size_t server_public_key_size,
    const std::string& statechain_id, std::string& error_message) {
    if (!valid_statechain_id(statechain_id) || !server_public_key
        || server_public_key_size != BIP448_PUBLIC_KEY_SIZE) return false;
    try {
        const auto sealed = serialize_encrypted(encrypted_keypair);
        pqxx::connection connection(database_url());
        pqxx::work txn(connection);
        txn.exec_params(
            "INSERT INTO public.generated_public_key(statechain_id,sealed_keypair,public_key) VALUES($1,$2,$3)",
            statechain_id, bytes(sealed.data(), sealed.size()), bytes(server_public_key, server_public_key_size));
        txn.commit();
        return true;
    } catch (const std::exception&) {
        error_message = "generated public key could not be stored";
        return false;
    }
}


bool get_statechain_public_key(
    const std::string& statechain_id,
    bool& found,
    unsigned char* server_public_key,
    std::size_t server_public_key_size,
    std::string& error_message) {
    found = false;
    error_message.clear();
    if (!valid_statechain_id(statechain_id) || server_public_key == nullptr
        || server_public_key_size != BIP448_PUBLIC_KEY_SIZE) {
        error_message = "Statechain lookup requires a valid ID and 33-byte public key buffer.";
        return false;
    }
    try {
        pqxx::connection connection(database_url());
        pqxx::nontransaction txn(connection);
        const auto rows = txn.exec_params(
            "SELECT public_key FROM public.generated_public_key WHERE statechain_id=$1",
            statechain_id);
        if (rows.empty()) return true;
        Bip448PublicKey key{};
        if (rows.size() != 1 || !field_array(rows[0]["public_key"], key)) {
            error_message = "Stored statechain public key is malformed.";
            return false;
        }
        std::copy(key.begin(), key.end(), server_public_key);
        found = true;
        return true;
    } catch (const std::exception& error) {
        error_message = error.what();
        return false;
    }
}

Bip448Result observe_bip448_state(const std::string& statechain_id) {
    Bip448Result result;
    if (!valid_statechain_id(statechain_id)) { result.outcome = Bip448Outcome::InvalidInput; return result; }
    try {
        pqxx::connection connection(database_url());
        pqxx::work txn(connection);
        const auto rows = txn.exec_params(
            "SELECT sig_count,key_generation,public_key FROM public.generated_public_key WHERE statechain_id=$1", statechain_id);
        if (rows.empty()) { txn.commit(); result.outcome = Bip448Outcome::NotFound; return result; }
        Bip448State state{statechain_id, rows[0]["sig_count"].as<std::int64_t>(), rows[0]["key_generation"].as<std::int64_t>()};
        if (rows.size() != 1 || state.sig_count < 0 || state.key_generation < 0
            || !field_array(rows[0]["public_key"], state.server_pubkey)) throw std::runtime_error("invalid state");
        txn.commit();
        result.outcome = Bip448Outcome::Applied;
        result.state = std::move(state);
    } catch (const std::exception&) {}
    return result;
}

Bip448Result execute_bip448_sign_first(const Bip448SignFirstRequest& request, unsigned char* seed) {
    Bip448Result result;
    if (!seed || !valid_statechain_id(request.statechain_id)
        || !lower_hex_string(request.signing_id, 64) || request.expected_key_generation < 0) {
        result.outcome = Bip448Outcome::InvalidInput; return result;
    }
    try {
        pqxx::connection connection(database_url());
        pqxx::work txn(connection);
        LockedParent parent;
        if (!lock_parent(txn, request.statechain_id, parent)) { txn.commit(); result.outcome = Bip448Outcome::NotFound; return result; }
        if (!parent_matches(parent, request.expected_key_generation, request.expected_server_pubkey, result)) return result;
        LockedNonce existing;
        if (lock_nonce(txn, request.statechain_id, request.signing_id, existing)) {
            if (existing.generation != parent.generation) { result.outcome = Bip448Outcome::OperationConflict; return result; }
            txn.commit(); result.outcome = Bip448Outcome::ExactReplay;
            result.value = lower_hex(existing.nonce.data(), existing.nonce.size()); return result;
        }
        auto keypair = deserialize_encrypted(parent.sealed);
        if (!keypair) throw std::runtime_error("invalid keypair");
        auto generated = enclave::generate_nonce(seed, keypair.get());
        EncryptedBufferGuard guard{generated.encrypted_secnonce};
        Bip448PublicNonce public_nonce{};
        std::copy(std::begin(generated.server_pubnonce), std::end(generated.server_pubnonce), public_nonce.begin());
        const auto sealed_nonce = serialize_encrypted(generated.encrypted_secnonce);
        txn.exec_params(
            "INSERT INTO public.bip448_nonce_state(statechain_id,signing_id,key_generation,public_nonce,sealed_secnonce) VALUES($1,$2,$3,$4,$5)",
            request.statechain_id, request.signing_id, parent.generation,
            bytes(public_nonce.data(), public_nonce.size()), bytes(sealed_nonce.data(), sealed_nonce.size()));
        txn.commit(); result.outcome = Bip448Outcome::Applied;
        result.value = lower_hex(public_nonce.data(), public_nonce.size());
    } catch (const std::exception&) {}
    return result;
}

Bip448Result execute_bip448_sign_second(const Bip448SignSecondRequest& request, unsigned char* seed) {
    Bip448Result result;
    if (!seed || !valid_statechain_id(request.statechain_id) || !lower_hex_string(request.signing_id, 64)
        || request.expected_key_generation < 0 || request.session.size() != 133
        || (request.negate_seckey != 0 && request.negate_seckey != 1)) {
        result.outcome = Bip448Outcome::InvalidInput; return result;
    }
    try {
        pqxx::connection connection(database_url());
        pqxx::work txn(connection);
        LockedParent parent;
        if (!lock_parent(txn, request.statechain_id, parent)) { txn.commit(); result.outcome = Bip448Outcome::NotFound; return result; }
        if (!parent_matches(parent, request.expected_key_generation, request.expected_server_pubkey, result)) return result;
        LockedNonce nonce;
        if (!lock_nonce(txn, request.statechain_id, request.signing_id, nonce)) { txn.commit(); result.outcome = Bip448Outcome::NotFound; return result; }
        if (nonce.generation != parent.generation || !equal(nonce.nonce, request.server_pubnonce)) {
            result.outcome = Bip448Outcome::OperationConflict; return result;
        }
        const std::string challenge = lower_hex(
            request.session.data() + SESSION_CHALLENGE_OFFSET, SESSION_CHALLENGE_SIZE);
        if (nonce.partial) {
            if (!nonce.challenge || *nonce.challenge != challenge || !nonce.negate
                || *nonce.negate != request.negate_seckey) { result.outcome = Bip448Outcome::OperationConflict; return result; }
            txn.commit(); result.outcome = Bip448Outcome::ExactReplay; result.value = *nonce.partial; return result;
        }
        if (nonce.challenge && (*nonce.challenge != challenge || !nonce.negate
                || *nonce.negate != request.negate_seckey)) {
            result.outcome = Bip448Outcome::OperationConflict; return result;
        }
        if (parent.count == std::numeric_limits<std::int64_t>::max()) { result.outcome = Bip448Outcome::Overflow; return result; }
        auto keypair = deserialize_encrypted(parent.sealed);
        auto secnonce = deserialize_encrypted(nonce.sealed);
        if (!keypair || !secnonce) throw std::runtime_error("invalid signing state");
        auto session = request.session;
        auto public_nonce = request.server_pubnonce;
        auto generated = enclave::partial_signature(seed, keypair.get(), secnonce.get(), request.negate_seckey,
            session.data(), session.size(), public_nonce.data());
        OPENSSL_cleanse(session.data(), session.size());
        const std::string partial = lower_hex(generated.partial_sig_data, sizeof(generated.partial_sig_data));
        OPENSSL_cleanse(generated.partial_sig_data, sizeof(generated.partial_sig_data));
        const auto saved = txn.exec_params(
            "UPDATE public.bip448_nonce_state SET challenge=$1,negate_seckey=$2,partial_sig=$3,updated_at=NOW() WHERE id=$4 AND partial_sig IS NULL RETURNING id",
            challenge, request.negate_seckey, partial, nonce.id);
        const auto count = txn.exec_params(
            "UPDATE public.generated_public_key SET sig_count=sig_count+1 WHERE statechain_id=$1 AND key_generation=$2 AND public_key=$3 AND sig_count<$4 RETURNING sig_count",
            request.statechain_id, parent.generation, bytes(parent.key.data(), parent.key.size()),
            std::numeric_limits<std::int64_t>::max());
        if (saved.size() != 1 || count.size() != 1
            || count[0]["sig_count"].as<std::int64_t>() != parent.count + 1) throw std::runtime_error("sign commit failed");
        txn.commit(); result.outcome = Bip448Outcome::Applied; result.value = partial;
        result.actual_sig_count = parent.count + 1;
    } catch (const std::exception&) {}
    return result;
}

Bip448Result execute_bip448_keyupdate(const Bip448KeyupdateRequest& request, unsigned char* seed) {
    Bip448Result result;
    std::string hash;
    if (!seed || !request_hash(request, hash)) { result.outcome = Bip448Outcome::InvalidInput; return result; }
    try {
        pqxx::connection connection(database_url());
        pqxx::work txn(connection);
        LockedParent parent;
        if (!lock_parent(txn, request.statechain_id, parent)) { txn.commit(); result.outcome = Bip448Outcome::NotFound; return result; }
        result.actual_sig_count = parent.count; result.actual_key_generation = parent.generation;
        const auto stored = txn.exec_params(
            "SELECT request_hash,accepted_sig_count,previous_key_generation,resulting_key_generation,previous_server_pubkey,resulting_server_pubkey,transfer_generation_pubkey FROM public.bip448_keyupdate_receipt WHERE statechain_id=$1 AND operation_id=$2 FOR UPDATE",
            request.statechain_id, request.operation_id);
        if (!stored.empty()) {
            const std::string stored_hash = stored[0]["request_hash"].as<std::string>();
            if (stored.size() != 1 || stored_hash.size() != hash.size()
                || CRYPTO_memcmp(stored_hash.data(), hash.data(), hash.size()) != 0) {
                result.outcome = Bip448Outcome::OperationConflict; return result;
            }
            Bip448Receipt receipt{request.operation_id, request.statechain_id,
                stored[0]["accepted_sig_count"].as<std::int64_t>(),
                stored[0]["previous_key_generation"].as<std::int64_t>(),
                stored[0]["resulting_key_generation"].as<std::int64_t>()};
            if (!field_array(stored[0]["previous_server_pubkey"], receipt.previous_server_pubkey)
                || !field_array(stored[0]["resulting_server_pubkey"], receipt.resulting_server_pubkey)
                || !field_array(stored[0]["transfer_generation_pubkey"], receipt.transfer_generation_pubkey)) throw std::runtime_error("invalid receipt");
            txn.commit(); result.outcome = Bip448Outcome::ExactReplay; result.receipt = std::move(receipt); return result;
        }
        if (parent.count != request.expected_sig_count) { result.outcome = Bip448Outcome::SignatureCountMismatch; return result; }
        if (!parent_matches(parent, request.expected_key_generation, request.expected_server_pubkey, result)) return result;
        if (parent.generation == std::numeric_limits<std::int64_t>::max()) { result.outcome = Bip448Outcome::Overflow; return result; }
        Bip448PublicKey transfer{}, expected{};
        if (!keyupdate_public_keys(request, parent.key, transfer, expected)) { result.outcome = Bip448Outcome::KeyupdateRejected; return result; }
        auto keypair = deserialize_encrypted(parent.sealed);
        if (!keypair) throw std::runtime_error("invalid keypair");
        auto x1 = request.x1; auto t2 = request.t2;
        auto generated = enclave::key_update(seed, keypair.get(), x1.data(), t2.data());
        OPENSSL_cleanse(x1.data(), x1.size()); OPENSSL_cleanse(t2.data(), t2.size());
        EncryptedBufferGuard guard{generated.encrypted_data};
        Bip448PublicKey actual{};
        std::copy(std::begin(generated.server_pubkey), std::end(generated.server_pubkey), actual.begin());
        if (!equal(actual, expected)) { result.outcome = Bip448Outcome::KeyupdateRejected; return result; }
        const auto sealed = serialize_encrypted(generated.encrypted_data);
        txn.exec_params(
            "INSERT INTO public.bip448_keyupdate_receipt(statechain_id,operation_id,request_hash,accepted_sig_count,previous_key_generation,resulting_key_generation,previous_server_pubkey,resulting_server_pubkey,transfer_generation_pubkey) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            request.statechain_id, request.operation_id, hash, parent.count, parent.generation, parent.generation + 1,
            bytes(parent.key.data(), parent.key.size()), bytes(expected.data(), expected.size()), bytes(transfer.data(), transfer.size()));
        const auto updated = txn.exec_params(
            "UPDATE public.generated_public_key SET sealed_keypair=$1,public_key=$2,key_generation=key_generation+1 WHERE statechain_id=$3 AND sig_count=$4 AND key_generation=$5 AND public_key=$6 RETURNING key_generation",
            bytes(sealed.data(), sealed.size()), bytes(expected.data(), expected.size()), request.statechain_id,
            parent.count, parent.generation, bytes(parent.key.data(), parent.key.size()));
        if (updated.size() != 1 || updated[0]["key_generation"].as<std::int64_t>() != parent.generation + 1) {
            result.outcome = Bip448Outcome::KeyupdateRejected; return result;
        }
        txn.exec_params("DELETE FROM public.bip448_nonce_state WHERE statechain_id=$1 AND key_generation=$2",
            request.statechain_id, parent.generation);
        txn.commit();
        result.outcome = Bip448Outcome::Applied;
        result.receipt = Bip448Receipt{request.operation_id, request.statechain_id, parent.count,
            parent.generation, parent.generation + 1, parent.key, expected, transfer};
    } catch (const std::exception&) {}
    return result;
}

Bip448Result delete_statechain(const std::string& statechain_id) {
    Bip448Result result;
    if (!valid_statechain_id(statechain_id)) { result.outcome = Bip448Outcome::InvalidInput; return result; }
    try {
        pqxx::connection connection(database_url());
        pqxx::work txn(connection);
        const auto parent = txn.exec_params(
            "SELECT id FROM public.generated_public_key WHERE statechain_id=$1 FOR UPDATE", statechain_id);
        if (!parent.empty()) txn.exec_params("DELETE FROM public.generated_public_key WHERE statechain_id=$1", statechain_id);
        txn.commit(); result.outcome = Bip448Outcome::Applied;
    } catch (const std::exception&) {}
    return result;
}

bool valid_statechain_id(const std::string& value) noexcept {
    return !value.empty() && value.size() <= 50 && value.find('\0') == std::string::npos;
}

} // namespace db_manager
