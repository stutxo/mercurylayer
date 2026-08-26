#include "db_manager.h"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <secp256k1.h>

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "utils.h"
#include "enclave.h"

namespace db_manager {

    namespace {

        constexpr int kSchemaVersion = 2;
        constexpr int kBusyTimeoutMilliseconds = 5000;
        constexpr size_t kEncryptedDataHeaderSize =
            sizeof(size_t) + sizeof(utils::chacha20_poly1305_encrypted_data::nonce) +
            sizeof(utils::chacha20_poly1305_encrypted_data::mac);
        constexpr std::size_t kMaxSealedSize = 4096;
        constexpr std::size_t kSessionChallengeOffset = 69;
        constexpr std::size_t kSessionChallengeSize = 32;

        constexpr const char* kGeneratedKeysSchemaSql = R"sql(
CREATE TABLE generated_public_key (
    statechain_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(CAST(statechain_id AS BLOB)) BETWEEN 1 AND 50 AND
        instr(statechain_id, char(0)) = 0
    ),
    sealed_keypair BLOB NOT NULL CHECK (
        typeof(sealed_keypair) = 'blob' AND
        length(sealed_keypair) >= 48 AND length(sealed_keypair) <= 4096
    ),
    public_key BLOB NOT NULL UNIQUE CHECK (
        typeof(public_key) = 'blob' AND length(public_key) = 33
    ),
    sig_count INTEGER NOT NULL DEFAULT 0 CHECK (
        typeof(sig_count) = 'integer' AND sig_count >= 0
    ),
    key_generation INTEGER NOT NULL DEFAULT 0 CHECK (
        typeof(key_generation) = 'integer' AND key_generation >= 0
    )
) WITHOUT ROWID
)sql";

        constexpr const char* kNonceSchemaSql = R"sql(
CREATE TABLE bip448_nonce_state (
    id INTEGER PRIMARY KEY,
    statechain_id TEXT NOT NULL,
    signing_id TEXT NOT NULL CHECK (
        length(signing_id) = 64 AND signing_id NOT GLOB '*[^0-9a-f]*'
    ),
    key_generation INTEGER NOT NULL CHECK (
        typeof(key_generation) = 'integer' AND key_generation >= 0
    ),
    public_nonce BLOB NOT NULL CHECK (
        typeof(public_nonce) = 'blob' AND length(public_nonce) = 66
    ),
    sealed_secnonce BLOB NOT NULL CHECK (
        typeof(sealed_secnonce) = 'blob' AND
        length(sealed_secnonce) >= 48 AND length(sealed_secnonce) <= 4096
    ),
    challenge TEXT CHECK (
        challenge IS NULL OR
        (length(challenge) = 64 AND challenge NOT GLOB '*[^0-9a-f]*')
    ),
    negate_seckey INTEGER CHECK (negate_seckey IS NULL OR negate_seckey IN (0, 1)),
    partial_sig TEXT CHECK (
        partial_sig IS NULL OR
        (length(partial_sig) = 64 AND partial_sig NOT GLOB '*[^0-9a-f]*')
    ),
    UNIQUE (statechain_id, signing_id),
    FOREIGN KEY (statechain_id) REFERENCES generated_public_key(statechain_id)
        ON DELETE CASCADE,
    CHECK (
        (challenge IS NULL AND negate_seckey IS NULL AND partial_sig IS NULL) OR
        (challenge IS NOT NULL AND negate_seckey IS NOT NULL)
    )
)
)sql";

        constexpr const char* kReceiptSchemaSql = R"sql(
CREATE TABLE bip448_keyupdate_receipt (
    statechain_id TEXT NOT NULL,
    operation_id TEXT NOT NULL CHECK (
        length(operation_id) = 64 AND operation_id NOT GLOB '*[^0-9a-f]*'
    ),
    request_hash TEXT NOT NULL CHECK (
        length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'
    ),
    accepted_sig_count INTEGER NOT NULL CHECK (accepted_sig_count >= 0),
    previous_key_generation INTEGER NOT NULL CHECK (previous_key_generation >= 0),
    resulting_key_generation INTEGER NOT NULL CHECK (
        resulting_key_generation = previous_key_generation + 1
    ),
    previous_server_pubkey BLOB NOT NULL CHECK (length(previous_server_pubkey) = 33),
    resulting_server_pubkey BLOB NOT NULL CHECK (length(resulting_server_pubkey) = 33),
    transfer_generation_pubkey BLOB NOT NULL CHECK (length(transfer_generation_pubkey) = 33),
    PRIMARY KEY (statechain_id, operation_id),
    FOREIGN KEY (statechain_id) REFERENCES generated_public_key(statechain_id)
        ON DELETE CASCADE
) WITHOUT ROWID
)sql";

        constexpr const char* kMetadataSchemaSql = R"sql(
CREATE TABLE lockbox_metadata (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    seed_verifier BLOB NOT NULL CHECK (
        typeof(seed_verifier) = 'blob' AND length(seed_verifier) = 32
    )
) WITHOUT ROWID
)sql";
        constexpr char kSeedVerifierDomain[] = "mercury-lockbox-sqlite-seed-v1";

        [[noreturn]] void throw_sqlite_error(sqlite3* database, const std::string& context) {
            const char* detail = database == nullptr ? nullptr : sqlite3_errmsg(database);
            throw std::runtime_error(
                context + (detail == nullptr ? std::string() : ": " + std::string(detail))
            );
        }

#ifdef __linux__
        [[noreturn]] void throw_file_error(const std::string& context) {
            const int error = errno;
            throw std::runtime_error(context + ": " + std::strerror(error));
        }
#endif

        void secure_database_file(const std::string& path, bool create) {
#ifdef __linux__
            int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW;
            if (create) {
                flags |= O_CREAT;
            }

            const int file = ::open(path.c_str(), flags, S_IRUSR | S_IWUSR);
            if (file < 0) {
                throw_file_error("Unable to open SQLite database file");
            }

            try {
                struct stat status {};
                if (::fstat(file, &status) != 0) {
                    throw_file_error("Unable to inspect SQLite database file");
                }
                if (!S_ISREG(status.st_mode)) {
                    throw std::runtime_error("SQLite database path is not a regular file.");
                }
                if (::fchmod(file, S_IRUSR | S_IWUSR) != 0) {
                    throw_file_error("Unable to set SQLite database file permissions");
                }

                if (::fstat(file, &status) != 0) {
                    throw_file_error("Unable to verify SQLite database file permissions");
                }
                if ((status.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
                    throw std::runtime_error("SQLite database file permissions are not 0600.");
                }
            } catch (...) {
                ::close(file);
                throw;
            }

            if (::close(file) != 0) {
                throw_file_error("Unable to close SQLite database file");
            }
#else
            (void) path;
            (void) create;
#endif
        }

        void sync_parent_directory(const std::string& path) {
#ifdef __linux__
            const std::filesystem::path database_path(path);
            const std::filesystem::path parent = database_path.parent_path().empty()
                ? std::filesystem::path(".")
                : database_path.parent_path();
            const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (directory < 0) {
                throw_file_error("Unable to open SQLite database directory");
            }
            if (::fsync(directory) != 0) {
                const int error = errno;
                ::close(directory);
                errno = error;
                throw_file_error("Unable to sync SQLite database directory");
            }
            if (::close(directory) != 0) {
                throw_file_error("Unable to close SQLite database directory");
            }
#else
            (void) path;
#endif
        }

        class Statement {
        public:
            Statement(sqlite3* database, const char* sql) : database_(database) {
                const int result = sqlite3_prepare_v2(database_, sql, -1, &statement_, nullptr);
                if (result != SQLITE_OK) {
                    throw_sqlite_error(database_, "Unable to prepare SQLite statement");
                }
            }

            ~Statement() {
                sqlite3_finalize(statement_);
            }

            Statement(const Statement&) = delete;
            Statement& operator=(const Statement&) = delete;

            void bind_text(int index, const std::string& value) {
                if (value.size() > static_cast<size_t>(INT_MAX)) {
                    throw std::runtime_error("SQLite text value is too large.");
                }
                const int result = sqlite3_bind_text(
                    statement_,
                    index,
                    value.data(),
                    static_cast<int>(value.size()),
                    SQLITE_TRANSIENT
                );
                if (result != SQLITE_OK) {
                    throw_sqlite_error(database_, "Unable to bind SQLite text value");
                }
            }

            void bind_blob(int index, const unsigned char* value, size_t size) {
                if (size > static_cast<size_t>(INT_MAX)) {
                    throw std::runtime_error("SQLite blob value is too large.");
                }

                const int result = size == 0
                    ? sqlite3_bind_zeroblob(statement_, index, 0)
                    : sqlite3_bind_blob(
                        statement_,
                        index,
                        value,
                        static_cast<int>(size),
                        SQLITE_TRANSIENT
                    );
                if (result != SQLITE_OK) {
                    throw_sqlite_error(database_, "Unable to bind SQLite blob value");
                }
            }

            void bind_int64(int index, std::int64_t value) {
                if (sqlite3_bind_int64(statement_, index, value) != SQLITE_OK) {
                    throw_sqlite_error(database_, "Unable to bind SQLite integer value");
                }
            }

            void bind_int(int index, int value) {
                if (sqlite3_bind_int(statement_, index, value) != SQLITE_OK) {
                    throw_sqlite_error(database_, "Unable to bind SQLite integer value");
                }
            }

            int step() {
                const int result = sqlite3_step(statement_);
                if (result != SQLITE_ROW && result != SQLITE_DONE) {
                    throw_sqlite_error(database_, "Unable to execute SQLite statement");
                }
                return result;
            }

            sqlite3_stmt* get() const {
                return statement_;
            }

        private:
            sqlite3* database_ = nullptr;
            sqlite3_stmt* statement_ = nullptr;
        };

        void execute_sql(sqlite3* database, const char* sql, const std::string& context) {
            char* sqlite_error = nullptr;
            const int result = sqlite3_exec(database, sql, nullptr, nullptr, &sqlite_error);
            if (result == SQLITE_OK) {
                return;
            }

            std::string detail = sqlite_error == nullptr
                ? std::string(sqlite3_errmsg(database))
                : std::string(sqlite_error);
            sqlite3_free(sqlite_error);
            throw std::runtime_error(context + ": " + detail);
        }

        int64_t query_integer(sqlite3* database, const char* sql) {
            Statement statement(database, sql);
            if (statement.step() != SQLITE_ROW ||
                sqlite3_column_type(statement.get(), 0) != SQLITE_INTEGER) {
                throw std::runtime_error("SQLite query did not return an integer.");
            }

            const int64_t value = sqlite3_column_int64(statement.get(), 0);
            if (statement.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite query returned more than one row.");
            }
            return value;
        }

        std::string query_text(sqlite3* database, const char* sql) {
            Statement statement(database, sql);
            if (statement.step() != SQLITE_ROW ||
                sqlite3_column_type(statement.get(), 0) != SQLITE_TEXT) {
                throw std::runtime_error("SQLite query did not return text.");
            }

            const auto* value = sqlite3_column_text(statement.get(), 0);
            const int size = sqlite3_column_bytes(statement.get(), 0);
            std::string result(reinterpret_cast<const char*>(value), static_cast<size_t>(size));
            if (statement.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite query returned more than one row.");
            }
            return result;
        }

        void configure_connection(sqlite3* database) {
            std::string journal_mode = query_text(database, "PRAGMA journal_mode=DELETE;");
            std::transform(
                journal_mode.begin(),
                journal_mode.end(),
                journal_mode.begin(),
                [](unsigned char character) { return static_cast<char>(std::tolower(character)); }
            );
            if (journal_mode != "delete") {
                throw std::runtime_error("SQLite journal_mode is not DELETE.");
            }

            execute_sql(database, "PRAGMA synchronous=EXTRA;", "Unable to configure SQLite synchronous mode");
            execute_sql(database, "PRAGMA foreign_keys=ON;", "Unable to enable SQLite foreign keys");
            execute_sql(database, "PRAGMA trusted_schema=OFF;", "Unable to disable SQLite trusted schema");
            execute_sql(database, "PRAGMA temp_store=MEMORY;", "Unable to configure SQLite temporary storage");

            if (query_integer(database, "PRAGMA synchronous;") != 3) {
                throw std::runtime_error("SQLite synchronous mode is not EXTRA.");
            }
            if (query_integer(database, "PRAGMA foreign_keys;") != 1) {
                throw std::runtime_error("SQLite foreign keys are not enabled.");
            }
            if (query_integer(database, "PRAGMA trusted_schema;") != 0) {
                throw std::runtime_error("SQLite trusted schema is not disabled.");
            }
            if (query_integer(database, "PRAGMA temp_store;") != 2) {
                throw std::runtime_error("SQLite temporary storage is not in memory.");
            }
        }

        class Database {
        public:
            Database(const std::string& path, bool create) {
                secure_database_file(path, create);

                int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;
                if (create) {
                    flags |= SQLITE_OPEN_CREATE;
                }

                const int result = sqlite3_open_v2(path.c_str(), &database_, flags, nullptr);
                if (result != SQLITE_OK) {
                    const std::string detail = database_ == nullptr
                        ? std::string(sqlite3_errstr(result))
                        : std::string(sqlite3_errmsg(database_));
                    sqlite3_close(database_);
                    database_ = nullptr;
                    throw std::runtime_error("Unable to open SQLite database: " + detail);
                }

                try {
                    sqlite3_extended_result_codes(database_, 1);
                    if (sqlite3_busy_timeout(database_, kBusyTimeoutMilliseconds) != SQLITE_OK) {
                        throw_sqlite_error(database_, "Unable to configure SQLite busy timeout");
                    }
                    configure_connection(database_);
                } catch (...) {
                    sqlite3_close(database_);
                    database_ = nullptr;
                    throw;
                }
            }

            ~Database() {
                sqlite3_close(database_);
            }

            Database(const Database&) = delete;
            Database& operator=(const Database&) = delete;

            sqlite3* get() const {
                return database_;
            }

        private:
            sqlite3* database_ = nullptr;
        };

        class Transaction {
        public:
            explicit Transaction(sqlite3* database) : database_(database) {
                execute_sql(database_, "BEGIN IMMEDIATE;", "Unable to begin SQLite transaction");
            }

            ~Transaction() {
                if (active_) {
                    sqlite3_exec(database_, "ROLLBACK;", nullptr, nullptr, nullptr);
                }
            }

            Transaction(const Transaction&) = delete;
            Transaction& operator=(const Transaction&) = delete;

            void commit() {
                execute_sql(database_, "COMMIT;", "Unable to commit SQLite transaction");
                active_ = false;
            }

        private:
            sqlite3* database_ = nullptr;
            bool active_ = true;
        };

        std::string normalize_schema(std::string schema) {
            std::string normalized;
            normalized.reserve(schema.size());
            bool in_single_quote = false;
            bool in_double_quote = false;
            for (size_t index = 0; index < schema.size(); ++index) {
                const unsigned char character = static_cast<unsigned char>(schema[index]);
                if (character == '\'' && !in_double_quote) {
                    normalized.push_back(static_cast<char>(character));
                    if (in_single_quote && index + 1 < schema.size() && schema[index + 1] == '\'') {
                        normalized.push_back(schema[++index]);
                    } else {
                        in_single_quote = !in_single_quote;
                    }
                    continue;
                }
                if (character == '"' && !in_single_quote) {
                    in_double_quote = !in_double_quote;
                    normalized.push_back(static_cast<char>(character));
                    continue;
                }
                if (!in_single_quote && !in_double_quote &&
                    (std::isspace(character) != 0 || character == ';')) {
                    continue;
                }
                normalized.push_back(
                    in_single_quote || in_double_quote
                        ? static_cast<char>(character)
                        : static_cast<char>(std::tolower(character))
                );
            }
            return normalized;
        }

        bool has_user_tables(sqlite3* database) {
            Statement statement(
                database,
                "SELECT 1 FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' LIMIT 1;"
            );
            return statement.step() == SQLITE_ROW;
        }

        void validate_table_schema(
            sqlite3* database,
            const std::string& table,
            const std::string& expected_schema
        ) {
            Statement statement(
                database,
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1;"
            );
            statement.bind_text(1, table);
            if (statement.step() != SQLITE_ROW ||
                sqlite3_column_type(statement.get(), 0) != SQLITE_TEXT) {
                throw std::runtime_error("SQLite Lockbox schema is missing table " + table + ".");
            }

            const auto* schema_text = sqlite3_column_text(statement.get(), 0);
            const int schema_size = sqlite3_column_bytes(statement.get(), 0);
            std::string stored_schema(
                reinterpret_cast<const char*>(schema_text),
                static_cast<size_t>(schema_size)
            );
            if (normalize_schema(stored_schema) != normalize_schema(expected_schema)) {
                throw std::runtime_error(
                    "SQLite Lockbox schema for " + table + " does not match version 2."
                );
            }
            if (statement.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite Lockbox schema is ambiguous.");
            }
        }

        void validate_schema(sqlite3* database) {
            const int64_t version = query_integer(database, "PRAGMA user_version;");
            if (version > kSchemaVersion) {
                throw std::runtime_error(
                    "SQLite schema version " + std::to_string(version) +
                    " is newer than supported version " + std::to_string(kSchemaVersion) + "."
                );
            }
            if (version != kSchemaVersion) {
                throw std::runtime_error("SQLite database schema version is not 2.");
            }

            validate_table_schema(database, "generated_public_key", kGeneratedKeysSchemaSql);
            validate_table_schema(database, "bip448_nonce_state", kNonceSchemaSql);
            validate_table_schema(database, "bip448_keyupdate_receipt", kReceiptSchemaSql);
            validate_table_schema(database, "lockbox_metadata", kMetadataSchemaSql);

            Statement unexpected_object(
                database,
                "SELECT name FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' "
                "AND NOT (type = 'table' AND name IN "
                "('generated_public_key', 'bip448_nonce_state', "
                "'bip448_keyupdate_receipt', 'lockbox_metadata')) LIMIT 1;"
            );
            if (unexpected_object.step() == SQLITE_ROW) {
                throw std::runtime_error("SQLite Lockbox schema contains unexpected objects.");
            }

            Statement generated_columns(
                database,
                "SELECT statechain_id,sealed_keypair,public_key,sig_count,key_generation "
                "FROM generated_public_key LIMIT 0;"
            );
            Statement nonce_columns(
                database,
                "SELECT id,statechain_id,signing_id,key_generation,public_nonce,"
                "sealed_secnonce,challenge,negate_seckey,partial_sig "
                "FROM bip448_nonce_state LIMIT 0;"
            );
            Statement receipt_columns(
                database,
                "SELECT statechain_id,operation_id,request_hash,accepted_sig_count,"
                "previous_key_generation,resulting_key_generation,previous_server_pubkey,"
                "resulting_server_pubkey,transfer_generation_pubkey "
                "FROM bip448_keyupdate_receipt LIMIT 0;"
            );
            Statement metadata_row(
                database,
                "SELECT seed_verifier FROM lockbox_metadata WHERE singleton = 1;"
            );
            if (metadata_row.step() != SQLITE_ROW ||
                sqlite3_column_type(metadata_row.get(), 0) != SQLITE_BLOB ||
                sqlite3_column_bytes(metadata_row.get(), 0) != 32 ||
                metadata_row.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite seed verifier is missing or malformed.");
            }
        }

        void verify_integrity(sqlite3* database) {
            if (query_text(database, "PRAGMA quick_check;") != "ok") {
                throw std::runtime_error("SQLite database integrity check failed.");
            }
        }

        std::string get_database_path() {
            return utils::getStringConfigVar(utils::DATABASE_PATH);
        }

        std::array<unsigned char, 32> seed_verifier(
            const unsigned char* seed,
            size_t seed_size
        ) {
            if (seed == nullptr || seed_size != 32) {
                throw std::runtime_error("SQLite storage requires a 32-byte wrapping seed.");
            }

            std::array<unsigned char, 32> verifier {};
            unsigned int verifier_size = 0;
            const auto* result = HMAC(
                EVP_sha256(),
                seed,
                static_cast<int>(seed_size),
                reinterpret_cast<const unsigned char*>(kSeedVerifierDomain),
                sizeof(kSeedVerifierDomain) - 1,
                verifier.data(),
                &verifier_size
            );
            if (result == nullptr || verifier_size != verifier.size()) {
                throw std::runtime_error("Unable to compute SQLite seed verifier.");
            }
            return verifier;
        }

        void insert_seed_verifier(
            sqlite3* database,
            const std::array<unsigned char, 32>& verifier
        ) {
            Statement statement(
                database,
                "INSERT INTO lockbox_metadata (singleton, seed_verifier) VALUES (1, ?1);"
            );
            statement.bind_blob(1, verifier.data(), verifier.size());
            if (statement.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite seed verifier insert did not complete.");
            }
        }

        void verify_seed(
            sqlite3* database,
            const std::array<unsigned char, 32>& expected_verifier
        ) {
            Statement statement(
                database,
                "SELECT seed_verifier FROM lockbox_metadata WHERE singleton = 1;"
            );
            if (statement.step() != SQLITE_ROW ||
                sqlite3_column_type(statement.get(), 0) != SQLITE_BLOB ||
                sqlite3_column_bytes(statement.get(), 0) !=
                    static_cast<int>(expected_verifier.size())) {
                throw std::runtime_error("SQLite seed verifier is missing or malformed.");
            }
            const void* stored_verifier = sqlite3_column_blob(statement.get(), 0);
            if (stored_verifier == nullptr ||
                CRYPTO_memcmp(
                    stored_verifier,
                    expected_verifier.data(),
                    expected_verifier.size()
                ) != 0) {
                throw std::runtime_error("SQLite database does not match the wrapping seed.");
            }
            if (statement.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite seed verifier is ambiguous.");
            }
        }

        std::vector<unsigned char> serialize_blob(
            const utils::chacha20_poly1305_encrypted_data& source
        ) {
            if (source.data_len == 0 ||
                source.data_len > kMaxSealedSize - kEncryptedDataHeaderSize) {
                throw std::runtime_error("Encrypted data is too large to serialize.");
            }
            if (source.data == nullptr) {
                throw std::runtime_error("Encrypted data payload is missing.");
            }

            std::vector<unsigned char> serialized(kEncryptedDataHeaderSize + source.data_len);
            size_t offset = 0;
            std::memcpy(serialized.data() + offset, &source.data_len, sizeof(source.data_len));
            offset += sizeof(source.data_len);
            std::memcpy(serialized.data() + offset, source.nonce, sizeof(source.nonce));
            offset += sizeof(source.nonce);
            std::memcpy(serialized.data() + offset, source.mac, sizeof(source.mac));
            offset += sizeof(source.mac);
            if (source.data_len != 0) {
                std::memcpy(serialized.data() + offset, source.data, source.data_len);
            }
            return serialized;
        }

        bool serialized_blob_is_valid(const unsigned char* buffer, size_t buffer_size) {
            if (buffer == nullptr || buffer_size < kEncryptedDataHeaderSize ||
                buffer_size > kMaxSealedSize) {
                return false;
            }

            size_t data_length = 0;
            std::memcpy(&data_length, buffer, sizeof(data_length));
            return data_length > 0 &&
                data_length <= buffer_size - kEncryptedDataHeaderSize &&
                data_length + kEncryptedDataHeaderSize == buffer_size;
        }

        bool deserialize_blob(
            const unsigned char* buffer,
            size_t buffer_size,
            utils::chacha20_poly1305_encrypted_data* destination
        ) {
            if (destination == nullptr || !serialized_blob_is_valid(buffer, buffer_size)) {
                return false;
            }

            size_t data_length = 0;
            std::memcpy(&data_length, buffer, sizeof(data_length));
            std::unique_ptr<unsigned char[]> data(new (std::nothrow) unsigned char[data_length]);
            if (data_length != 0 && data == nullptr) {
                return false;
            }

            size_t offset = sizeof(data_length);
            unsigned char nonce[sizeof(destination->nonce)];
            unsigned char mac[sizeof(destination->mac)];
            std::memcpy(nonce, buffer + offset, sizeof(nonce));
            offset += sizeof(nonce);
            std::memcpy(mac, buffer + offset, sizeof(mac));
            offset += sizeof(mac);
            if (data_length != 0) {
                std::memcpy(data.get(), buffer + offset, data_length);
            }

            destination->data_len = data_length;
            std::memcpy(destination->nonce, nonce, sizeof(nonce));
            std::memcpy(destination->mac, mac, sizeof(mac));
            destination->data = data.release();
            return true;
        }

        bool load_encrypted_blob(
            sqlite3_stmt* statement,
            int column,
            std::unique_ptr<utils::chacha20_poly1305_encrypted_data>& destination
        ) {
            if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
                destination.reset();
                return true;
            }
            if (sqlite3_column_type(statement, column) != SQLITE_BLOB) {
                return false;
            }

            const auto* sealed_data = static_cast<const unsigned char*>(
                sqlite3_column_blob(statement, column)
            );
            const size_t sealed_size = static_cast<size_t>(
                sqlite3_column_bytes(statement, column)
            );
            if (!serialized_blob_is_valid(sealed_data, sealed_size)) {
                return false;
            }
            return destination == nullptr ||
                deserialize_blob(sealed_data, sealed_size, destination.get());
        }

        void set_error(std::string& error_message, const std::exception& error) {
            error_message = error.what();
        }

        void set_unknown_error(std::string& error_message) {
            error_message = "Unknown SQLite database error.";
        }

        constexpr char kKeyupdateDomain[] = "BIP448/lockbox-keyupdate/v2\0";

        std::vector<unsigned char> column_blob(sqlite3_stmt* statement, int column) {
            if (sqlite3_column_type(statement, column) != SQLITE_BLOB) {
                throw std::runtime_error("SQLite column is not a blob.");
            }
            const int size = sqlite3_column_bytes(statement, column);
            const auto* value = static_cast<const unsigned char*>(
                sqlite3_column_blob(statement, column)
            );
            if (size <= 0 || value == nullptr) {
                throw std::runtime_error("SQLite blob is empty.");
            }
            return std::vector<unsigned char>(value, value + size);
        }

        template <std::size_t N>
        bool column_array(sqlite3_stmt* statement, int column, std::array<unsigned char, N>& output) {
            if (sqlite3_column_type(statement, column) != SQLITE_BLOB ||
                sqlite3_column_bytes(statement, column) != static_cast<int>(N)) {
                return false;
            }
            const void* value = sqlite3_column_blob(statement, column);
            if (value == nullptr) return false;
            std::memcpy(output.data(), value, N);
            return true;
        }

        std::string column_text(sqlite3_stmt* statement, int column) {
            if (sqlite3_column_type(statement, column) != SQLITE_TEXT) {
                throw std::runtime_error("SQLite column is not text.");
            }
            const auto* value = sqlite3_column_text(statement, column);
            const int size = sqlite3_column_bytes(statement, column);
            if (value == nullptr || size < 0) {
                throw std::runtime_error("SQLite text is malformed.");
            }
            return std::string(reinterpret_cast<const char*>(value), static_cast<std::size_t>(size));
        }

        std::optional<std::string> optional_text(sqlite3_stmt* statement, int column) {
            if (sqlite3_column_type(statement, column) == SQLITE_NULL) return std::nullopt;
            return column_text(statement, column);
        }

        std::optional<int> optional_int(sqlite3_stmt* statement, int column) {
            if (sqlite3_column_type(statement, column) == SQLITE_NULL) return std::nullopt;
            if (sqlite3_column_type(statement, column) != SQLITE_INTEGER) {
                throw std::runtime_error("SQLite column is not an integer.");
            }
            return sqlite3_column_int(statement, column);
        }

        template <std::size_t N>
        bool arrays_equal(
            const std::array<unsigned char, N>& left,
            const std::array<unsigned char, N>& right
        ) {
            return CRYPTO_memcmp(left.data(), right.data(), N) == 0;
        }

        struct EncryptedDeleter {
            void operator()(utils::chacha20_poly1305_encrypted_data* value) const {
                if (value == nullptr) return;
                if (value->data != nullptr) {
                    OPENSSL_cleanse(value->data, value->data_len);
                    delete[] value->data;
                }
                delete value;
            }
        };
        using EncryptedPtr =
            std::unique_ptr<utils::chacha20_poly1305_encrypted_data, EncryptedDeleter>;

        EncryptedPtr deserialize_encrypted(const std::vector<unsigned char>& value) {
            EncryptedPtr result(new utils::chacha20_poly1305_encrypted_data{});
            if (!deserialize_blob(value.data(), value.size(), result.get())) return {};
            return result;
        }

        struct EncryptedBufferGuard {
            utils::chacha20_poly1305_encrypted_data& value;
            ~EncryptedBufferGuard() {
                if (value.data != nullptr) {
                    OPENSSL_cleanse(value.data, value.data_len);
                    delete[] value.data;
                    value.data = nullptr;
                }
            }
        };

        std::string lower_hex(const unsigned char* data, std::size_t size) {
            constexpr char digits[] = "0123456789abcdef";
            std::string result(size * 2, '0');
            for (std::size_t index = 0; index < size; ++index) {
                result[index * 2] = digits[data[index] >> 4];
                result[index * 2 + 1] = digits[data[index] & 0x0f];
            }
            return result;
        }

        bool lower_hex_string(const std::string& value, std::size_t size) {
            return value.size() == size &&
                std::all_of(value.begin(), value.end(), [](unsigned char character) {
                    return (character >= '0' && character <= '9') ||
                        (character >= 'a' && character <= 'f');
                });
        }

        void append_u32(std::vector<unsigned char>& output, std::uint32_t value) {
            for (int shift = 24; shift >= 0; shift -= 8) {
                output.push_back(static_cast<unsigned char>(value >> shift));
            }
        }

        void append_u64(std::vector<unsigned char>& output, std::uint64_t value) {
            for (int shift = 56; shift >= 0; shift -= 8) {
                output.push_back(static_cast<unsigned char>(value >> shift));
            }
        }

        std::string sha256_hex(const std::vector<unsigned char>& value) {
            std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
            SHA256(value.data(), value.size(), digest.data());
            return lower_hex(digest.data(), digest.size());
        }

        bool decode_operation_id(
            const std::string& value,
            std::array<unsigned char, 32>& output
        ) {
            if (!lower_hex_string(value, 64)) return false;
            auto digit = [](char character) {
                return character <= '9' ? character - '0' : character - 'a' + 10;
            };
            for (std::size_t index = 0; index < output.size(); ++index) {
                output[index] = static_cast<unsigned char>(
                    (digit(value[index * 2]) << 4) | digit(value[index * 2 + 1])
                );
            }
            return true;
        }

        bool request_hash(const Bip448KeyupdateRequest& request, std::string& output) {
            std::array<unsigned char, 32> operation{};
            if (!decode_operation_id(request.operation_id, operation) ||
                !valid_statechain_id(request.statechain_id) ||
                request.expected_sig_count < 0 ||
                request.expected_key_generation < 0) {
                return false;
            }
            std::vector<unsigned char> preimage(
                std::begin(kKeyupdateDomain),
                std::end(kKeyupdateDomain) - 1
            );
            preimage.push_back(2);
            preimage.insert(preimage.end(), operation.begin(), operation.end());
            append_u32(preimage, static_cast<std::uint32_t>(request.statechain_id.size()));
            preimage.insert(
                preimage.end(),
                request.statechain_id.begin(),
                request.statechain_id.end()
            );
            preimage.insert(preimage.end(), request.t2.begin(), request.t2.end());
            preimage.insert(preimage.end(), request.x1.begin(), request.x1.end());
            append_u64(preimage, static_cast<std::uint64_t>(request.expected_sig_count));
            append_u64(preimage, static_cast<std::uint64_t>(request.expected_key_generation));
            preimage.insert(
                preimage.end(),
                request.expected_server_pubkey.begin(),
                request.expected_server_pubkey.end()
            );
            output = sha256_hex(preimage);
            return true;
        }

        using SecpPtr =
            std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>;

        bool keyupdate_public_keys(
            const Bip448KeyupdateRequest& request,
            const Bip448PublicKey& current,
            Bip448PublicKey& transfer,
            Bip448PublicKey& resulting
        ) {
            SecpPtr context(
                secp256k1_context_create(SECP256K1_CONTEXT_VERIFY),
                secp256k1_context_destroy
            );
            if (!context ||
                !secp256k1_ec_seckey_verify(context.get(), request.t2.data()) ||
                !secp256k1_ec_seckey_verify(context.get(), request.x1.data())) {
                return false;
            }
            secp256k1_pubkey current_key;
            secp256k1_pubkey t2_key;
            secp256k1_pubkey x1_key;
            if (!secp256k1_ec_pubkey_parse(
                    context.get(),
                    &current_key,
                    current.data(),
                    current.size()) ||
                !secp256k1_ec_pubkey_create(context.get(), &t2_key, request.t2.data()) ||
                !secp256k1_ec_pubkey_create(context.get(), &x1_key, request.x1.data())) {
                return false;
            }
            std::size_t size = transfer.size();
            if (!secp256k1_ec_pubkey_serialize(
                    context.get(),
                    transfer.data(),
                    &size,
                    &x1_key,
                    SECP256K1_EC_COMPRESSED) ||
                size != transfer.size()) {
                return false;
            }
            secp256k1_pubkey plus_t2;
            secp256k1_pubkey neg_x1 = x1_key;
            secp256k1_pubkey final_key;
            const secp256k1_pubkey* first[] = {&current_key, &t2_key};
            if (!secp256k1_ec_pubkey_combine(context.get(), &plus_t2, first, 2) ||
                !secp256k1_ec_pubkey_negate(context.get(), &neg_x1)) {
                return false;
            }
            const secp256k1_pubkey* second[] = {&plus_t2, &neg_x1};
            if (!secp256k1_ec_pubkey_combine(context.get(), &final_key, second, 2)) {
                return false;
            }
            size = resulting.size();
            return secp256k1_ec_pubkey_serialize(
                       context.get(),
                       resulting.data(),
                       &size,
                       &final_key,
                       SECP256K1_EC_COMPRESSED) &&
                size == resulting.size();
        }

        struct LockedParent {
            std::vector<unsigned char> sealed;
            Bip448PublicKey key{};
            std::int64_t count{0};
            std::int64_t generation{0};
        };

        bool load_parent(sqlite3* database, const std::string& id, LockedParent& parent) {
            Statement statement(
                database,
                "SELECT sealed_keypair,public_key,sig_count,key_generation "
                "FROM generated_public_key WHERE statechain_id=?1;"
            );
            statement.bind_text(1, id);
            if (statement.step() == SQLITE_DONE) return false;
            parent.sealed = column_blob(statement.get(), 0);
            if (!column_array(statement.get(), 1, parent.key) ||
                sqlite3_column_type(statement.get(), 2) != SQLITE_INTEGER ||
                sqlite3_column_type(statement.get(), 3) != SQLITE_INTEGER) {
                throw std::runtime_error("Invalid generated-key row.");
            }
            parent.count = sqlite3_column_int64(statement.get(), 2);
            parent.generation = sqlite3_column_int64(statement.get(), 3);
            if (parent.count < 0 || parent.generation < 0 ||
                !serialized_blob_is_valid(parent.sealed.data(), parent.sealed.size()) ||
                statement.step() != SQLITE_DONE) {
                throw std::runtime_error("Invalid generated-key row.");
            }
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

        bool load_nonce(
            sqlite3* database,
            const std::string& statechain_id,
            const std::string& signing_id,
            LockedNonce& nonce
        ) {
            Statement statement(
                database,
                "SELECT id,key_generation,public_nonce,sealed_secnonce,challenge,"
                "negate_seckey,partial_sig FROM bip448_nonce_state "
                "WHERE statechain_id=?1 AND signing_id=?2;"
            );
            statement.bind_text(1, statechain_id);
            statement.bind_text(2, signing_id);
            if (statement.step() == SQLITE_DONE) return false;
            if (sqlite3_column_type(statement.get(), 0) != SQLITE_INTEGER ||
                sqlite3_column_type(statement.get(), 1) != SQLITE_INTEGER ||
                !column_array(statement.get(), 2, nonce.nonce)) {
                throw std::runtime_error("Invalid nonce row.");
            }
            nonce.id = sqlite3_column_int64(statement.get(), 0);
            nonce.generation = sqlite3_column_int64(statement.get(), 1);
            nonce.sealed = column_blob(statement.get(), 3);
            nonce.challenge = optional_text(statement.get(), 4);
            nonce.negate = optional_int(statement.get(), 5);
            nonce.partial = optional_text(statement.get(), 6);
            if (nonce.id <= 0 || nonce.generation < 0 ||
                !serialized_blob_is_valid(nonce.sealed.data(), nonce.sealed.size()) ||
                statement.step() != SQLITE_DONE) {
                throw std::runtime_error("Invalid nonce row.");
            }
            return true;
        }

        bool parent_matches(
            const LockedParent& parent,
            std::int64_t generation,
            const Bip448PublicKey& key,
            Bip448Result& result
        ) {
            result.actual_sig_count = parent.count;
            result.actual_key_generation = parent.generation;
            if (parent.generation != generation) {
                result.outcome = Bip448Outcome::KeyGenerationMismatch;
                return false;
            }
            if (!arrays_equal(parent.key, key)) {
                result.outcome = Bip448Outcome::ServerKeyMismatch;
                return false;
            }
            return true;
        }

    } // namespace

    bool initialize_database(
        std::string& error_message,
        const unsigned char* seed,
        size_t seed_size,
        bool allow_initialization
    ) {
        error_message.clear();
        try {
            const auto expected_verifier = seed_verifier(seed, seed_size);
            const std::string database_path = get_database_path();
            Database database(database_path, allow_initialization);
            Transaction transaction(database.get());

            const int64_t version = query_integer(database.get(), "PRAGMA user_version;");
            if (version > kSchemaVersion) {
                throw std::runtime_error(
                    "SQLite schema version " + std::to_string(version) +
                    " is newer than supported version " + std::to_string(kSchemaVersion) + "."
                );
            }
            if (version == 0) {
                if (!allow_initialization) {
                    throw std::runtime_error(
                        "Refusing to initialize an unversioned SQLite database on existing storage."
                    );
                }
                if (has_user_tables(database.get())) {
                    throw std::runtime_error("Unversioned SQLite database is not empty.");
                }
                execute_sql(
                    database.get(),
                    kGeneratedKeysSchemaSql,
                    "Unable to create SQLite generated-key schema"
                );
                execute_sql(
                    database.get(),
                    kNonceSchemaSql,
                    "Unable to create SQLite BIP448 nonce schema"
                );
                execute_sql(
                    database.get(),
                    kReceiptSchemaSql,
                    "Unable to create SQLite BIP448 receipt schema"
                );
                execute_sql(
                    database.get(),
                    kMetadataSchemaSql,
                    "Unable to create SQLite Lockbox metadata"
                );
                insert_seed_verifier(database.get(), expected_verifier);
                execute_sql(
                    database.get(),
                    "PRAGMA user_version=2;",
                    "Unable to set SQLite schema version"
                );
            } else if (version != kSchemaVersion) {
                throw std::runtime_error("Unsupported SQLite database schema version.");
            }

            validate_schema(database.get());
            verify_seed(database.get(), expected_verifier);
            transaction.commit();
            verify_integrity(database.get());
            sync_parent_directory(database_path);
            return true;
        } catch (const std::exception& error) {
            set_error(error_message, error);
            return false;
        } catch (...) {
            set_unknown_error(error_message);
            return false;
        }
    }

    bool database_is_ready(std::string& error_message) {
        error_message.clear();
        try {
            Database database(get_database_path(), false);
            validate_schema(database.get());
            verify_integrity(database.get());
            return true;
        } catch (const std::exception& error) {
            set_error(error_message, error);
            return false;
        } catch (...) {
            set_unknown_error(error_message);
            return false;
        }
    }

    bool save_generated_public_key(
        const utils::chacha20_poly1305_encrypted_data& encrypted_keypair,
        const unsigned char* server_public_key,
        std::size_t server_public_key_size,
        const std::string& statechain_id,
        std::string& error_message
    ) {
        error_message.clear();
        if (!valid_statechain_id(statechain_id) || server_public_key == nullptr ||
            server_public_key_size != BIP448_PUBLIC_KEY_SIZE) {
            error_message = "Invalid generated-key input.";
            return false;
        }
        try {
            const auto sealed_keypair = serialize_blob(encrypted_keypair);
            Database database(get_database_path(), false);
            validate_schema(database.get());
            Transaction transaction(database.get());
            Statement statement(
                database.get(),
                "INSERT INTO generated_public_key "
                "(statechain_id,sealed_keypair,public_key) VALUES (?1,?2,?3);"
            );
            statement.bind_text(1, statechain_id);
            statement.bind_blob(2, sealed_keypair.data(), sealed_keypair.size());
            statement.bind_blob(3, server_public_key, server_public_key_size);
            if (statement.step() != SQLITE_DONE || sqlite3_changes(database.get()) != 1) {
                throw std::runtime_error("SQLite generated-key insert did not complete.");
            }
            transaction.commit();
            return true;
        } catch (const std::exception& error) {
            set_error(error_message, error);
            return false;
        } catch (...) {
            set_unknown_error(error_message);
            return false;
        }
    }

    bool get_statechain_public_key(
        const std::string& statechain_id,
        bool& found,
        unsigned char* server_public_key,
        std::size_t server_public_key_size,
        std::string& error_message
    ) {
        found = false;
        error_message.clear();
        if (!valid_statechain_id(statechain_id) || server_public_key == nullptr ||
            server_public_key_size != BIP448_PUBLIC_KEY_SIZE) {
            error_message = "Statechain lookup requires a valid ID and 33-byte public key buffer.";
            return false;
        }
        try {
            Database database(get_database_path(), false);
            validate_schema(database.get());
            Statement statement(
                database.get(),
                "SELECT public_key FROM generated_public_key WHERE statechain_id=?1;"
            );
            statement.bind_text(1, statechain_id);
            if (statement.step() == SQLITE_DONE) return true;
            Bip448PublicKey key{};
            if (!column_array(statement.get(), 0, key) || statement.step() != SQLITE_DONE) {
                error_message = "Stored statechain public key is malformed.";
                return false;
            }
            std::copy(key.begin(), key.end(), server_public_key);
            found = true;
            return true;
        } catch (const std::exception& error) {
            set_error(error_message, error);
            return false;
        } catch (...) {
            set_unknown_error(error_message);
            return false;
        }
    }

    Bip448Result observe_bip448_state(const std::string& statechain_id) {
        Bip448Result result;
        if (!valid_statechain_id(statechain_id)) {
            result.outcome = Bip448Outcome::InvalidInput;
            return result;
        }
        try {
            Database database(get_database_path(), false);
            validate_schema(database.get());
            Statement statement(
                database.get(),
                "SELECT sig_count,key_generation,public_key "
                "FROM generated_public_key WHERE statechain_id=?1;"
            );
            statement.bind_text(1, statechain_id);
            if (statement.step() == SQLITE_DONE) {
                result.outcome = Bip448Outcome::NotFound;
                return result;
            }
            if (sqlite3_column_type(statement.get(), 0) != SQLITE_INTEGER ||
                sqlite3_column_type(statement.get(), 1) != SQLITE_INTEGER) {
                throw std::runtime_error("Invalid BIP448 state row.");
            }
            Bip448State state;
            state.statechain_id = statechain_id;
            state.sig_count = sqlite3_column_int64(statement.get(), 0);
            state.key_generation = sqlite3_column_int64(statement.get(), 1);
            if (state.sig_count < 0 || state.key_generation < 0 ||
                !column_array(statement.get(), 2, state.server_pubkey) ||
                statement.step() != SQLITE_DONE) {
                throw std::runtime_error("Invalid BIP448 state row.");
            }
            result.outcome = Bip448Outcome::Applied;
            result.state = std::move(state);
        } catch (const std::exception&) {
        }
        return result;
    }

    Bip448Result execute_bip448_sign_first(
        const Bip448SignFirstRequest& request,
        unsigned char* seed
    ) {
        Bip448Result result;
        if (seed == nullptr || !valid_statechain_id(request.statechain_id) ||
            !lower_hex_string(request.signing_id, 64) ||
            request.expected_key_generation < 0) {
            result.outcome = Bip448Outcome::InvalidInput;
            return result;
        }
        try {
            Database database(get_database_path(), false);
            validate_schema(database.get());
            Transaction transaction(database.get());
            LockedParent parent;
            if (!load_parent(database.get(), request.statechain_id, parent)) {
                transaction.commit();
                result.outcome = Bip448Outcome::NotFound;
                return result;
            }
            if (!parent_matches(
                    parent,
                    request.expected_key_generation,
                    request.expected_server_pubkey,
                    result)) {
                return result;
            }
            LockedNonce existing;
            if (load_nonce(
                    database.get(),
                    request.statechain_id,
                    request.signing_id,
                    existing)) {
                if (existing.generation != parent.generation) {
                    result.outcome = Bip448Outcome::OperationConflict;
                    return result;
                }
                transaction.commit();
                result.outcome = Bip448Outcome::ExactReplay;
                result.value = lower_hex(existing.nonce.data(), existing.nonce.size());
                return result;
            }

            auto keypair = deserialize_encrypted(parent.sealed);
            if (!keypair) throw std::runtime_error("Invalid encrypted keypair.");
            auto generated = enclave::generate_nonce(seed, keypair.get());
            EncryptedBufferGuard guard{generated.encrypted_secnonce};
            Bip448PublicNonce public_nonce{};
            std::copy(
                std::begin(generated.server_pubnonce),
                std::end(generated.server_pubnonce),
                public_nonce.begin()
            );
            const auto sealed_nonce = serialize_blob(generated.encrypted_secnonce);
            Statement insert(
                database.get(),
                "INSERT INTO bip448_nonce_state "
                "(statechain_id,signing_id,key_generation,public_nonce,sealed_secnonce) "
                "VALUES (?1,?2,?3,?4,?5);"
            );
            insert.bind_text(1, request.statechain_id);
            insert.bind_text(2, request.signing_id);
            insert.bind_int64(3, parent.generation);
            insert.bind_blob(4, public_nonce.data(), public_nonce.size());
            insert.bind_blob(5, sealed_nonce.data(), sealed_nonce.size());
            if (insert.step() != SQLITE_DONE || sqlite3_changes(database.get()) != 1) {
                throw std::runtime_error("SQLite nonce insert did not complete.");
            }
            transaction.commit();
            result.outcome = Bip448Outcome::Applied;
            result.value = lower_hex(public_nonce.data(), public_nonce.size());
        } catch (const std::exception&) {
        }
        return result;
    }

    Bip448Result execute_bip448_sign_second(
        const Bip448SignSecondRequest& request,
        unsigned char* seed
    ) {
        Bip448Result result;
        if (seed == nullptr || !valid_statechain_id(request.statechain_id) ||
            !lower_hex_string(request.signing_id, 64) ||
            request.expected_key_generation < 0 ||
            request.session.size() != 133 ||
            (request.negate_seckey != 0 && request.negate_seckey != 1)) {
            result.outcome = Bip448Outcome::InvalidInput;
            return result;
        }
        try {
            Database database(get_database_path(), false);
            validate_schema(database.get());
            Transaction transaction(database.get());
            LockedParent parent;
            if (!load_parent(database.get(), request.statechain_id, parent)) {
                transaction.commit();
                result.outcome = Bip448Outcome::NotFound;
                return result;
            }
            if (!parent_matches(
                    parent,
                    request.expected_key_generation,
                    request.expected_server_pubkey,
                    result)) {
                return result;
            }
            LockedNonce nonce;
            if (!load_nonce(
                    database.get(),
                    request.statechain_id,
                    request.signing_id,
                    nonce)) {
                transaction.commit();
                result.outcome = Bip448Outcome::NotFound;
                return result;
            }
            if (nonce.generation != parent.generation ||
                !arrays_equal(nonce.nonce, request.server_pubnonce)) {
                result.outcome = Bip448Outcome::OperationConflict;
                return result;
            }
            const std::string challenge = lower_hex(
                request.session.data() + kSessionChallengeOffset,
                kSessionChallengeSize
            );
            if (nonce.partial) {
                if (!nonce.challenge || *nonce.challenge != challenge || !nonce.negate ||
                    *nonce.negate != request.negate_seckey) {
                    result.outcome = Bip448Outcome::OperationConflict;
                    return result;
                }
                transaction.commit();
                result.outcome = Bip448Outcome::ExactReplay;
                result.value = *nonce.partial;
                return result;
            }
            if (nonce.challenge &&
                (*nonce.challenge != challenge || !nonce.negate ||
                 *nonce.negate != request.negate_seckey)) {
                result.outcome = Bip448Outcome::OperationConflict;
                return result;
            }
            if (parent.count == std::numeric_limits<std::int64_t>::max()) {
                result.outcome = Bip448Outcome::Overflow;
                return result;
            }

            auto keypair = deserialize_encrypted(parent.sealed);
            auto secnonce = deserialize_encrypted(nonce.sealed);
            if (!keypair || !secnonce) {
                throw std::runtime_error("Invalid encrypted signing state.");
            }
            auto session = request.session;
            auto public_nonce = request.server_pubnonce;
            auto generated = enclave::partial_signature(
                seed,
                keypair.get(),
                secnonce.get(),
                request.negate_seckey,
                session.data(),
                session.size(),
                public_nonce.data()
            );
            OPENSSL_cleanse(session.data(), session.size());
            const std::string partial =
                lower_hex(generated.partial_sig_data, sizeof(generated.partial_sig_data));
            OPENSSL_cleanse(generated.partial_sig_data, sizeof(generated.partial_sig_data));

            Statement save_nonce(
                database.get(),
                "UPDATE bip448_nonce_state SET challenge=?1,negate_seckey=?2,"
                "partial_sig=?3 WHERE id=?4 AND partial_sig IS NULL;"
            );
            save_nonce.bind_text(1, challenge);
            save_nonce.bind_int(2, request.negate_seckey);
            save_nonce.bind_text(3, partial);
            save_nonce.bind_int64(4, nonce.id);
            if (save_nonce.step() != SQLITE_DONE || sqlite3_changes(database.get()) != 1) {
                throw std::runtime_error("SQLite partial signature save failed.");
            }

            Statement update_count(
                database.get(),
                "UPDATE generated_public_key SET sig_count=sig_count+1 "
                "WHERE statechain_id=?1 AND key_generation=?2 AND public_key=?3 "
                "AND sig_count<?4;"
            );
            update_count.bind_text(1, request.statechain_id);
            update_count.bind_int64(2, parent.generation);
            update_count.bind_blob(3, parent.key.data(), parent.key.size());
            update_count.bind_int64(4, std::numeric_limits<std::int64_t>::max());
            if (update_count.step() != SQLITE_DONE || sqlite3_changes(database.get()) != 1) {
                throw std::runtime_error("SQLite signature count update failed.");
            }

            transaction.commit();
            result.outcome = Bip448Outcome::Applied;
            result.value = partial;
            result.actual_sig_count = parent.count + 1;
            result.actual_key_generation = parent.generation;
        } catch (const std::exception&) {
        }
        return result;
    }

    Bip448Result execute_bip448_keyupdate(
        const Bip448KeyupdateRequest& request,
        unsigned char* seed
    ) {
        Bip448Result result;
        std::string hash;
        if (seed == nullptr || !request_hash(request, hash)) {
            result.outcome = Bip448Outcome::InvalidInput;
            return result;
        }
        try {
            Database database(get_database_path(), false);
            validate_schema(database.get());
            Transaction transaction(database.get());
            LockedParent parent;
            if (!load_parent(database.get(), request.statechain_id, parent)) {
                transaction.commit();
                result.outcome = Bip448Outcome::NotFound;
                return result;
            }
            result.actual_sig_count = parent.count;
            result.actual_key_generation = parent.generation;

            Statement stored(
                database.get(),
                "SELECT request_hash,accepted_sig_count,previous_key_generation,"
                "resulting_key_generation,previous_server_pubkey,resulting_server_pubkey,"
                "transfer_generation_pubkey FROM bip448_keyupdate_receipt "
                "WHERE statechain_id=?1 AND operation_id=?2;"
            );
            stored.bind_text(1, request.statechain_id);
            stored.bind_text(2, request.operation_id);
            if (stored.step() == SQLITE_ROW) {
                const std::string stored_hash = column_text(stored.get(), 0);
                if (stored_hash.size() != hash.size() ||
                    CRYPTO_memcmp(stored_hash.data(), hash.data(), hash.size()) != 0) {
                    result.outcome = Bip448Outcome::OperationConflict;
                    return result;
                }
                if (sqlite3_column_type(stored.get(), 1) != SQLITE_INTEGER ||
                    sqlite3_column_type(stored.get(), 2) != SQLITE_INTEGER ||
                    sqlite3_column_type(stored.get(), 3) != SQLITE_INTEGER) {
                    throw std::runtime_error("Invalid keyupdate receipt.");
                }
                Bip448Receipt receipt;
                receipt.operation_id = request.operation_id;
                receipt.statechain_id = request.statechain_id;
                receipt.accepted_sig_count = sqlite3_column_int64(stored.get(), 1);
                receipt.previous_key_generation = sqlite3_column_int64(stored.get(), 2);
                receipt.resulting_key_generation = sqlite3_column_int64(stored.get(), 3);
                if (receipt.accepted_sig_count < 0 ||
                    receipt.previous_key_generation < 0 ||
                    receipt.resulting_key_generation != receipt.previous_key_generation + 1 ||
                    !column_array(stored.get(), 4, receipt.previous_server_pubkey) ||
                    !column_array(stored.get(), 5, receipt.resulting_server_pubkey) ||
                    !column_array(stored.get(), 6, receipt.transfer_generation_pubkey) ||
                    stored.step() != SQLITE_DONE) {
                    throw std::runtime_error("Invalid keyupdate receipt.");
                }
                transaction.commit();
                result.outcome = Bip448Outcome::ExactReplay;
                result.receipt = std::move(receipt);
                return result;
            }

            if (parent.count != request.expected_sig_count) {
                result.outcome = Bip448Outcome::SignatureCountMismatch;
                return result;
            }
            if (!parent_matches(
                    parent,
                    request.expected_key_generation,
                    request.expected_server_pubkey,
                    result)) {
                return result;
            }
            if (parent.generation == std::numeric_limits<std::int64_t>::max()) {
                result.outcome = Bip448Outcome::Overflow;
                return result;
            }
            Bip448PublicKey transfer{};
            Bip448PublicKey expected{};
            if (!keyupdate_public_keys(request, parent.key, transfer, expected)) {
                result.outcome = Bip448Outcome::KeyupdateRejected;
                return result;
            }
            auto keypair = deserialize_encrypted(parent.sealed);
            if (!keypair) throw std::runtime_error("Invalid encrypted keypair.");
            auto x1 = request.x1;
            auto t2 = request.t2;
            auto generated = enclave::key_update(seed, keypair.get(), x1.data(), t2.data());
            OPENSSL_cleanse(x1.data(), x1.size());
            OPENSSL_cleanse(t2.data(), t2.size());
            EncryptedBufferGuard guard{generated.encrypted_data};
            Bip448PublicKey actual{};
            std::copy(
                std::begin(generated.server_pubkey),
                std::end(generated.server_pubkey),
                actual.begin()
            );
            if (!arrays_equal(actual, expected)) {
                result.outcome = Bip448Outcome::KeyupdateRejected;
                return result;
            }
            const auto sealed = serialize_blob(generated.encrypted_data);

            Statement insert_receipt(
                database.get(),
                "INSERT INTO bip448_keyupdate_receipt "
                "(statechain_id,operation_id,request_hash,accepted_sig_count,"
                "previous_key_generation,resulting_key_generation,previous_server_pubkey,"
                "resulting_server_pubkey,transfer_generation_pubkey) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9);"
            );
            insert_receipt.bind_text(1, request.statechain_id);
            insert_receipt.bind_text(2, request.operation_id);
            insert_receipt.bind_text(3, hash);
            insert_receipt.bind_int64(4, parent.count);
            insert_receipt.bind_int64(5, parent.generation);
            insert_receipt.bind_int64(6, parent.generation + 1);
            insert_receipt.bind_blob(7, parent.key.data(), parent.key.size());
            insert_receipt.bind_blob(8, expected.data(), expected.size());
            insert_receipt.bind_blob(9, transfer.data(), transfer.size());
            if (insert_receipt.step() != SQLITE_DONE ||
                sqlite3_changes(database.get()) != 1) {
                throw std::runtime_error("SQLite keyupdate receipt insert failed.");
            }

            Statement update_parent(
                database.get(),
                "UPDATE generated_public_key SET sealed_keypair=?1,public_key=?2,"
                "key_generation=key_generation+1 WHERE statechain_id=?3 AND sig_count=?4 "
                "AND key_generation=?5 AND public_key=?6;"
            );
            update_parent.bind_blob(1, sealed.data(), sealed.size());
            update_parent.bind_blob(2, expected.data(), expected.size());
            update_parent.bind_text(3, request.statechain_id);
            update_parent.bind_int64(4, parent.count);
            update_parent.bind_int64(5, parent.generation);
            update_parent.bind_blob(6, parent.key.data(), parent.key.size());
            if (update_parent.step() != SQLITE_DONE ||
                sqlite3_changes(database.get()) != 1) {
                result.outcome = Bip448Outcome::KeyupdateRejected;
                return result;
            }

            Statement delete_nonces(
                database.get(),
                "DELETE FROM bip448_nonce_state "
                "WHERE statechain_id=?1 AND key_generation=?2;"
            );
            delete_nonces.bind_text(1, request.statechain_id);
            delete_nonces.bind_int64(2, parent.generation);
            if (delete_nonces.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite nonce cleanup failed.");
            }

            transaction.commit();
            result.outcome = Bip448Outcome::Applied;
            result.receipt = Bip448Receipt{
                request.operation_id,
                request.statechain_id,
                parent.count,
                parent.generation,
                parent.generation + 1,
                parent.key,
                expected,
                transfer,
            };
        } catch (const std::exception&) {
        }
        return result;
    }

    Bip448Result delete_statechain(const std::string& statechain_id) {
        Bip448Result result;
        if (!valid_statechain_id(statechain_id)) {
            result.outcome = Bip448Outcome::InvalidInput;
            return result;
        }
        try {
            Database database(get_database_path(), false);
            validate_schema(database.get());
            Transaction transaction(database.get());
            Statement statement(
                database.get(),
                "DELETE FROM generated_public_key WHERE statechain_id=?1;"
            );
            statement.bind_text(1, statechain_id);
            if (statement.step() != SQLITE_DONE) {
                throw std::runtime_error("SQLite statechain delete failed.");
            }
            transaction.commit();
            result.outcome = Bip448Outcome::Applied;
        } catch (const std::exception&) {
        }
        return result;
    }

    bool valid_statechain_id(const std::string& value) noexcept {
        return !value.empty() && value.size() <= 50 &&
            value.find('\0') == std::string::npos;
    }

} // namespace db_manager
