#include "request_auth.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace request_auth {
namespace {

constexpr size_t kTokenHexLength = 64;

bool parse_required(const char* value) {
    if (value == nullptr || *value == '\0' || std::string_view(value) == "0" ||
        std::string_view(value) == "false") {
        return false;
    }
    if (std::string_view(value) == "1" || std::string_view(value) == "true") {
        return true;
    }
    throw std::runtime_error("LOCKBOX_REQUIRE_AUTH must be 0, 1, false, or true.");
}

bool valid_token(std::string_view token) {
    return token.size() == kTokenHexLength &&
        std::all_of(token.begin(), token.end(), [](unsigned char character) {
            return std::isxdigit(character) != 0;
        });
}

} // namespace

Authenticator::Authenticator(bool required, std::string token) {
    if (!required) {
        return;
    }
    if (token.empty()) {
        throw std::runtime_error(
            "LOCKBOX_AUTH_TOKEN is required when LOCKBOX_REQUIRE_AUTH=1."
        );
    }
    if (!valid_token(token)) {
        throw std::runtime_error(
            "LOCKBOX_AUTH_TOKEN must contain exactly 64 hexadecimal characters."
        );
    }
    expected_header_ = "Bearer " + token;
}

Authenticator Authenticator::from_environment() {
    const bool required = parse_required(std::getenv("LOCKBOX_REQUIRE_AUTH"));
    const char* token = std::getenv("LOCKBOX_AUTH_TOKEN");
    return Authenticator(required, token == nullptr ? std::string() : std::string(token));
}

bool Authenticator::enabled() const noexcept {
    return !expected_header_.empty();
}

bool Authenticator::authorized(std::string_view authorization_header) const noexcept {
    if (!enabled()) {
        return true;
    }
    return authorization_header.size() == expected_header_.size() &&
        CRYPTO_memcmp(
            authorization_header.data(),
            expected_header_.data(),
            expected_header_.size()
        ) == 0;
}

} // namespace request_auth
