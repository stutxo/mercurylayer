#include "request_auth.h"

#include <cassert>
#include <stdexcept>
#include <string>

int main() {
    request_auth::Authenticator disabled(false, "");
    assert(!disabled.enabled());
    assert(disabled.authorized(""));
    assert(disabled.authorized("anything"));

    const std::string token(64, 'a');
    request_auth::Authenticator disabled_with_token(false, token);
    assert(!disabled_with_token.enabled());
    assert(disabled_with_token.authorized(""));
    request_auth::Authenticator enabled(true, token);
    assert(enabled.enabled());
    assert(enabled.authorized("Bearer " + token));
    assert(!enabled.authorized(token));
    assert(!enabled.authorized("Bearer " + std::string(64, 'b')));
    assert(!enabled.authorized("Bearer " + token + "0"));

    bool missing_rejected = false;
    try {
        request_auth::Authenticator missing(true, "");
    } catch (const std::runtime_error&) {
        missing_rejected = true;
    }
    assert(missing_rejected);

    bool malformed_rejected = false;
    try {
        request_auth::Authenticator malformed(true, std::string(64, 'z'));
    } catch (const std::runtime_error&) {
        malformed_rejected = true;
    }
    assert(malformed_rejected);

    return 0;
}
