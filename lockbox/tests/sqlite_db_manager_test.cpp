#include "db_manager.h"
#include "enclave.h"
#include "filesystem_key_manager.h"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        std::array<char, 40> path_template{};
        const std::string pattern = "/tmp/lockbox-sqlite-test-XXXXXX";
        std::copy(pattern.begin(), pattern.end(), path_template.begin());
        char* created = ::mkdtemp(path_template.data());
        if (created == nullptr) {
            throw std::runtime_error(
                "Unable to create temporary directory: " + std::string(std::strerror(errno))
            );
        }
        path_ = created;
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

class RawDatabase {
public:
    explicit RawDatabase(const std::filesystem::path& path) {
        if (sqlite3_open_v2(
                path.c_str(),
                &database_,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                nullptr) != SQLITE_OK) {
            throw std::runtime_error("Unable to open test database.");
        }
    }

    ~RawDatabase() { sqlite3_close(database_); }

    void execute(const char* sql) {
        char* error = nullptr;
        if (sqlite3_exec(database_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string message = error == nullptr ? sqlite3_errmsg(database_) : error;
            sqlite3_free(error);
            throw std::runtime_error("Test SQL failed: " + message);
        }
    }

    std::int64_t integer(const char* sql) {
        sqlite3_stmt* statement = nullptr;
        if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK ||
            sqlite3_step(statement) != SQLITE_ROW ||
            sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
            sqlite3_finalize(statement);
            throw std::runtime_error("Test integer query failed.");
        }
        const auto value = sqlite3_column_int64(statement, 0);
        sqlite3_finalize(statement);
        return value;
    }

    std::string text(const char* sql) {
        sqlite3_stmt* statement = nullptr;
        if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK ||
            sqlite3_step(statement) != SQLITE_ROW ||
            sqlite3_column_type(statement, 0) != SQLITE_TEXT) {
            sqlite3_finalize(statement);
            throw std::runtime_error("Test text query failed.");
        }
        const auto* value = sqlite3_column_text(statement, 0);
        const int size = sqlite3_column_bytes(statement, 0);
        std::string result(reinterpret_cast<const char*>(value), static_cast<std::size_t>(size));
        sqlite3_finalize(statement);
        return result;
    }

private:
    sqlite3* database_ = nullptr;
};

struct GeneratedKeyGuard {
    utils::chacha20_poly1305_encrypted_data& encrypted;
    ~GeneratedKeyGuard() {
        delete[] encrypted.data;
        encrypted.data = nullptr;
    }
};

std::array<unsigned char, 32> test_seed(unsigned char marker = 0x42) {
    std::array<unsigned char, 32> seed{};
    seed.fill(marker);
    return seed;
}

void set_path(const char* name, const std::filesystem::path& value) {
    if (::setenv(name, value.c_str(), 1) != 0) {
        throw std::runtime_error("Unable to set test environment variable.");
    }
}

void require_mode_0600(const std::filesystem::path& path) {
    struct stat status{};
    require(::stat(path.c_str(), &status) == 0, "Unable to inspect SQLite database.");
    require((status.st_mode & 0777) == 0600, "SQLite database is not mode 0600.");
}

void test_bip448_backend(const std::filesystem::path& directory) {
    const auto database_path = directory / "lockbox.sqlite3";
    set_path("LOCKBOX_DATABASE_PATH", database_path);
    const auto seed = test_seed();
    std::string error;

    require(
        db_manager::initialize_database(error, seed.data(), seed.size(), true),
        "Database initialization failed: " + error
    );
    require(
        db_manager::initialize_database(error, seed.data(), seed.size(), false),
        "Database reopen failed: " + error
    );
    const auto wrong_seed = test_seed(0x43);
    require(
        !db_manager::initialize_database(error, wrong_seed.data(), wrong_seed.size(), false),
        "Database accepted the wrong wrapping seed"
    );
    require(error.find("does not match") != std::string::npos, "Seed mismatch was unclear.");
    require(db_manager::database_is_ready(error), "Readiness failed: " + error);
    require_mode_0600(database_path);

    {
        RawDatabase database(database_path);
        require(database.integer("PRAGMA user_version;") == 2, "Schema version is not 2.");
        require(database.text("PRAGMA journal_mode;") == "delete", "Journal mode is not DELETE.");
        require(database.integer("PRAGMA synchronous;") == 2 ||
                    database.integer("PRAGMA synchronous;") == 3,
                "SQLite synchronous mode is invalid.");
        require(
            database.integer(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' "
                "AND name IN ('generated_public_key','bip448_nonce_state',"
                "'bip448_keyupdate_receipt','lockbox_metadata');"
            ) == 4,
            "BIP448 SQLite tables are missing."
        );
    }

    auto generated = enclave::generate_new_keypair(const_cast<unsigned char*>(seed.data()));
    GeneratedKeyGuard generated_guard{generated.encrypted_data};
    const std::string statechain_id = "bip448-sqlite-state";
    require(
        db_manager::save_generated_public_key(
            generated.encrypted_data,
            generated.server_pubkey,
            sizeof(generated.server_pubkey),
            statechain_id,
            error),
        "Generated key save failed: " + error
    );

    db_manager::Bip448PublicKey initial_key{};
    std::copy(
        std::begin(generated.server_pubkey),
        std::end(generated.server_pubkey),
        initial_key.begin()
    );
    auto observed = db_manager::observe_bip448_state(statechain_id);
    require(observed.outcome == db_manager::Bip448Outcome::Applied, "State was not observed.");
    require(observed.state.has_value(), "Observed state is missing.");
    require(observed.state->sig_count == 0, "Initial signature count is not zero.");
    require(observed.state->key_generation == 0, "Initial key generation is not zero.");
    require(observed.state->server_pubkey == initial_key, "Initial server key changed.");

    bool found = false;
    db_manager::Bip448PublicKey public_key{};
    require(
        db_manager::get_statechain_public_key(
            statechain_id,
            found,
            public_key.data(),
            public_key.size(),
            error) && found && public_key == initial_key,
        "Public verification key lookup failed: " + error
    );

    db_manager::Bip448SignFirstRequest first;
    first.statechain_id = statechain_id;
    first.signing_id = std::string(64, 'a');
    first.expected_key_generation = 0;
    first.expected_server_pubkey = initial_key;
    const auto first_result = db_manager::execute_bip448_sign_first(
        first,
        const_cast<unsigned char*>(seed.data())
    );
    require(first_result.outcome == db_manager::Bip448Outcome::Applied, "Nonce was not created.");
    require(first_result.value.size() == 132, "Public nonce has the wrong size.");
    const auto first_replay = db_manager::execute_bip448_sign_first(
        first,
        const_cast<unsigned char*>(seed.data())
    );
    require(
        first_replay.outcome == db_manager::Bip448Outcome::ExactReplay &&
            first_replay.value == first_result.value,
        "Exact nonce retry did not replay."
    );

    auto stale_first = first;
    stale_first.expected_key_generation = 1;
    require(
        db_manager::execute_bip448_sign_first(
            stale_first,
            const_cast<unsigned char*>(seed.data())
        ).outcome == db_manager::Bip448Outcome::KeyGenerationMismatch,
        "Wrong-generation nonce request was accepted."
    );

    db_manager::Bip448KeyupdateRequest update;
    update.operation_id = std::string(64, 'b');
    update.statechain_id = statechain_id;
    update.t2.back() = 2;
    update.x1.back() = 3;
    update.expected_sig_count = 0;
    update.expected_key_generation = 0;
    update.expected_server_pubkey = initial_key;
    const auto updated = db_manager::execute_bip448_keyupdate(
        update,
        const_cast<unsigned char*>(seed.data())
    );
    require(updated.outcome == db_manager::Bip448Outcome::Applied, "Key update was not applied.");
    require(updated.receipt.has_value(), "Key update receipt is missing.");
    require(updated.receipt->previous_server_pubkey == initial_key, "Receipt previous key differs.");
    require(updated.receipt->resulting_key_generation == 1, "Receipt generation is wrong.");

    const auto update_replay = db_manager::execute_bip448_keyupdate(
        update,
        const_cast<unsigned char*>(seed.data())
    );
    require(
        update_replay.outcome == db_manager::Bip448Outcome::ExactReplay &&
            update_replay.receipt.has_value() &&
            update_replay.receipt->operation_id == updated.receipt->operation_id &&
            update_replay.receipt->resulting_server_pubkey ==
                updated.receipt->resulting_server_pubkey,
        "Exact key-update retry did not replay."
    );

    observed = db_manager::observe_bip448_state(statechain_id);
    require(observed.outcome == db_manager::Bip448Outcome::Applied, "Updated state is missing.");
    require(observed.state->key_generation == 1, "Key generation did not advance.");
    require(
        observed.state->server_pubkey == updated.receipt->resulting_server_pubkey,
        "Stored server key does not match the receipt."
    );

    auto next_first = first;
    next_first.expected_key_generation = 1;
    next_first.expected_server_pubkey = observed.state->server_pubkey;
    const auto next_nonce = db_manager::execute_bip448_sign_first(
        next_first,
        const_cast<unsigned char*>(seed.data())
    );
    require(
        next_nonce.outcome == db_manager::Bip448Outcome::Applied,
        "Old-generation nonce was not removed by key update."
    );

    require(
        db_manager::delete_statechain(statechain_id).outcome ==
            db_manager::Bip448Outcome::Applied,
        "Statechain delete failed."
    );
    require(
        db_manager::observe_bip448_state(statechain_id).outcome ==
            db_manager::Bip448Outcome::NotFound,
        "Deleted statechain remains visible."
    );
    found = true;
    require(
        db_manager::get_statechain_public_key(
            statechain_id,
            found,
            public_key.data(),
            public_key.size(),
            error) && !found,
        "Deleted public key remains visible."
    );
}

void test_storage_pair_guard(const std::filesystem::path& directory) {
    const auto seed_path = directory / "lockbox.seed";
    const auto database_path = directory / "lockbox.sqlite3";
    set_path("SEED_FILEPATH", seed_path);
    set_path("LOCKBOX_DATABASE_PATH", database_path);
    require(
        filesystem_key_manager::embedded_storage_needs_initialization(),
        "Empty embedded storage did not request initialization."
    );

    {
        std::ofstream seed(seed_path, std::ios::binary);
        seed << std::string(32, 'x');
    }
    bool rejected = false;
    try {
        (void)filesystem_key_manager::embedded_storage_needs_initialization();
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, "Incomplete seed/database pair was accepted.");
}

void test_newer_schema_rejected(const std::filesystem::path& directory) {
    const auto database_path = directory / "newer.sqlite3";
    set_path("LOCKBOX_DATABASE_PATH", database_path);
    const auto seed = test_seed(0x51);
    std::string error;
    require(
        db_manager::initialize_database(error, seed.data(), seed.size(), true),
        "Newer-schema fixture initialization failed: " + error
    );
    {
        RawDatabase database(database_path);
        database.execute("PRAGMA user_version=3;");
    }
    require(
        !db_manager::initialize_database(error, seed.data(), seed.size(), false),
        "Newer SQLite schema was accepted."
    );
}

} // namespace

int main() {
    try {
        TemporaryDirectory backend_directory;
        test_bip448_backend(backend_directory.path());

        TemporaryDirectory pair_directory;
        test_storage_pair_guard(pair_directory.path());

        TemporaryDirectory schema_directory;
        test_newer_schema_rejected(schema_directory.path());

        std::cout << "BIP448 SQLite Lockbox tests passed" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BIP448 SQLite Lockbox test failed: " << error.what() << std::endl;
        return 1;
    }
}
