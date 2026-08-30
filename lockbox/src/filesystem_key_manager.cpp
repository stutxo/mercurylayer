#include "filesystem_key_manager.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <optional>
#include <vector>
#include <utility>

#include <openssl/rand.h>

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "utils.h"

namespace filesystem_key_manager {

    namespace {

#ifdef LOCKBOX_DATABASE_BACKEND_SQLITE
        bool nonempty_regular_file(const std::string& path, const std::string& description) {
            std::error_code error;
            const bool exists = std::filesystem::exists(path, error);
            if (error) {
                throw std::runtime_error("Error checking " + description + ".");
            }
            if (!exists) {
                return false;
            }
            if (!std::filesystem::is_regular_file(path, error) || error) {
                throw std::runtime_error(description + " is not a regular file.");
            }
            const auto size = std::filesystem::file_size(path, error);
            if (error) {
                throw std::runtime_error("Error reading " + description + " size.");
            }
            return size > 0;
        }

        void refuse_seed_recreation_with_existing_database() {
            const std::string database_path = utils::getStringConfigVar(utils::DATABASE_PATH);
            if (nonempty_regular_file(database_path, "SQLite database")) {
                throw std::runtime_error(
                    "Refusing to generate a new seed while a nonempty SQLite database exists."
                );
            }
        }
#endif

#ifdef __linux__
        [[noreturn]] void throw_errno(const std::string& message) {
            const int error = errno;
            throw std::runtime_error(message + ": " + std::strerror(error));
        }

        std::optional<std::vector<uint8_t>> read_existing_seed_securely(
            const std::string& seed_file
        ) {
            int seed_fd = ::open(seed_file.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (seed_fd < 0) {
                if (errno == ENOENT) {
                    return std::nullopt;
                }
                throw_errno("Error opening seed file for reading");
            }

            try {
                struct stat metadata {};
                if (::fstat(seed_fd, &metadata) != 0) {
                    throw_errno("Error inspecting seed file");
                }
                if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1) {
                    throw std::runtime_error(
                        "Seed file must be a regular file with one hard link."
                    );
                }
                if (metadata.st_uid != ::geteuid()) {
                    throw std::runtime_error("Seed file must be owned by the Lockbox user.");
                }
                if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
                    throw std::runtime_error(
                        "Seed file must not be accessible by group or other users."
                    );
                }
                if (metadata.st_size != 32) {
                    throw std::runtime_error("Seed file has invalid size.");
                }

                std::vector<uint8_t> key(32);
                size_t offset = 0;
                while (offset < key.size()) {
                    const ssize_t result =
                        ::read(seed_fd, key.data() + offset, key.size() - offset);
                    if (result < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        throw_errno("Error reading seed file");
                    }
                    if (result == 0) {
                        throw std::runtime_error("Seed file has invalid size.");
                    }
                    offset += static_cast<size_t>(result);
                }

                unsigned char trailing_byte = 0;
                ssize_t trailing_result;
                do {
                    trailing_result = ::read(seed_fd, &trailing_byte, 1);
                } while (trailing_result < 0 && errno == EINTR);
                if (trailing_result < 0) {
                    throw_errno("Error reading seed file");
                }
                if (trailing_result != 0) {
                    throw std::runtime_error("Seed file has invalid size.");
                }

                const int fd_to_close = seed_fd;
                seed_fd = -1;
                if (::close(fd_to_close) != 0) {
                    throw_errno("Error closing seed file");
                }
                return key;
            } catch (...) {
                if (seed_fd >= 0) {
                    ::close(seed_fd);
                }
                throw;
            }
        }

        bool write_seed_durably(
            const std::string& seed_file,
            const std::vector<uint8_t>& key
        ) {
            const std::filesystem::path seed_path(seed_file);
            const std::filesystem::path parent = seed_path.parent_path().empty()
                ? std::filesystem::path(".")
                : seed_path.parent_path();

            if (seed_path.filename().empty()) {
                throw std::runtime_error("Seed filepath must name a file.");
            }

            int directory_fd = -1;
            int seed_fd = -1;
            std::string temporary_path;

            try {
                directory_fd = ::open(
                    parent.c_str(),
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC
                );
                if (directory_fd < 0) {
                    throw_errno("Error opening seed directory");
                }

                std::string temporary_template =
                    (parent / ("." + seed_path.filename().string() + ".tmp.XXXXXX")).string();
                std::vector<char> temporary_name(
                    temporary_template.begin(),
                    temporary_template.end()
                );
                temporary_name.push_back('\0');

                seed_fd = ::mkstemp(temporary_name.data());
                if (seed_fd < 0) {
                    throw_errno("Error creating temporary seed file");
                }
                temporary_path = temporary_name.data();

                if (::fchmod(seed_fd, S_IRUSR | S_IWUSR) != 0) {
                    throw_errno("Error setting seed file permissions");
                }

                size_t written = 0;
                while (written < key.size()) {
                    const ssize_t result = ::write(
                        seed_fd,
                        key.data() + written,
                        key.size() - written
                    );
                    if (result < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        throw_errno("Error writing seed to file");
                    }
                    if (result == 0) {
                        throw std::runtime_error("Error writing seed to file: short write");
                    }
                    written += static_cast<size_t>(result);
                }

                if (::fsync(seed_fd) != 0) {
                    throw_errno("Error syncing seed file");
                }

                const int fd_to_close = seed_fd;
                seed_fd = -1;
                if (::close(fd_to_close) != 0) {
                    throw_errno("Error closing seed file");
                }

                if (::link(temporary_path.c_str(), seed_path.c_str()) != 0) {
                    if (errno != EEXIST) {
                        throw_errno("Error installing seed file");
                    }

                    if (::unlink(temporary_path.c_str()) != 0) {
                        throw_errno("Error removing unselected seed file");
                    }
                    temporary_path.clear();

                    if (::fsync(directory_fd) != 0) {
                        throw_errno("Error syncing seed directory");
                    }

                    const int directory_to_close = directory_fd;
                    directory_fd = -1;
                    if (::close(directory_to_close) != 0) {
                        throw_errno("Error closing seed directory");
                    }
                    return false;
                }

                if (::unlink(temporary_path.c_str()) != 0) {
                    throw_errno("Error removing installed seed temporary link");
                }
                temporary_path.clear();

                if (::fsync(directory_fd) != 0) {
                    throw_errno("Error syncing seed directory");
                }

                const int directory_to_close = directory_fd;
                directory_fd = -1;
                if (::close(directory_to_close) != 0) {
                    throw_errno("Error closing seed directory");
                }
                return true;
            } catch (...) {
                if (seed_fd >= 0) {
                    ::close(seed_fd);
                }
                if (!temporary_path.empty()) {
                    ::unlink(temporary_path.c_str());
                }
                if (directory_fd >= 0) {
                    ::close(directory_fd);
                }
                throw;
            }
        }
#endif

    } // namespace

    std::string getSeedFilePath() {
        return utils::getStringConfigVar(utils::SEED_FILEPATH);
    }

    bool embedded_storage_needs_initialization() {
#ifdef LOCKBOX_DATABASE_BACKEND_SQLITE
        const std::string seed_path = getSeedFilePath();
        const std::string database_path = utils::getStringConfigVar(utils::DATABASE_PATH);
        if (std::filesystem::path(seed_path) == std::filesystem::path(database_path)) {
            throw std::runtime_error("Seed and SQLite database paths must be distinct.");
        }

        const bool seed_exists = nonempty_regular_file(seed_path, "seed file");
        const bool database_exists = nonempty_regular_file(database_path, "SQLite database");
        if (seed_exists != database_exists) {
            throw std::runtime_error(
                "Incomplete embedded Lockbox storage: seed and SQLite database must exist together."
            );
        }
        return !seed_exists;
#else
        return false;
#endif
    }

    std::vector<uint8_t> get_seed() {
        const std::string seed_file = getSeedFilePath();

#ifdef __linux__
        if (auto existing = read_existing_seed_securely(seed_file)) {
            return std::move(*existing);
        }
#else
        if (std::filesystem::exists(seed_file)) {
            std::ifstream seed_in(seed_file, std::ios::binary);
            if (!seed_in) {
                throw std::runtime_error("Error opening seed file for reading.");
            }
            std::vector<uint8_t> key((std::istreambuf_iterator<char>(seed_in)),
                                    std::istreambuf_iterator<char>());
            if (key.size() != 32) {
                throw std::runtime_error("Seed file has invalid size.");
            }
            return key;
        }
#endif

#ifdef LOCKBOX_DATABASE_BACKEND_SQLITE
        refuse_seed_recreation_with_existing_database();
#endif

        std::vector<uint8_t> key(32);
        if (RAND_bytes(key.data(), key.size()) != 1) {
            throw std::runtime_error("Error generating random bytes.");
        }

#ifdef __linux__
        if (!write_seed_durably(seed_file, key)) {
            return get_seed();
        }
#else
        std::ofstream seed_out(seed_file, std::ios::binary | std::ios::trunc);
        if (!seed_out) {
            throw std::runtime_error("Error opening seed file for writing.");
        }

        seed_out.write(reinterpret_cast<const char*>(key.data()), key.size());
        if (!seed_out) {
            throw std::runtime_error("Error writing seed file.");
        }

#ifdef __unix__
        seed_out.close();
        std::filesystem::permissions(
            seed_file,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace
        );
#endif
#endif

        return key;
    }

}
