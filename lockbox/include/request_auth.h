#pragma once

#include <string>
#include <string_view>

namespace request_auth {

class Authenticator {
public:
    Authenticator(bool required, std::string token);

    static Authenticator from_environment();

    bool enabled() const noexcept;
    bool authorized(std::string_view authorization_header) const noexcept;

private:
    std::string expected_header_;
};

} // namespace request_auth
