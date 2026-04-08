#ifndef UTILS_H
#define UTILS_H

#include <cstddef>
#include <stdint.h>
#include <string_view>
#include <vector>
#include <iomanip>
#include <string>

namespace utils {

    // config vars
    struct config_var
    {
        std::string env_var;
        std::string toml_var_1;
        std::string toml_var_2;
    };

    static const config_var DATABASE_URL = {"LOCKBOX_DATABASE_URL", "general", "database_connection_string"};
    static const config_var KEY_MANAGER = {"KEY_MANAGER", "general", "key_manager"};
    static const config_var SERVER_PORT = {"LOCKBOX_PORT", "general", "server_port"};

    static const config_var SEED_FILEPATH = {"SEED_FILEPATH", "filesystem", "seed_filepath"};

    static const config_var GCLOUD_PROJECT_ID = {"GCLOUD_PROJECT_ID", "gcloud", "project_id"};
    static const config_var GCLOUD_PROJECT_NUMBER = {"GCLOUD_PROJECT_NUMBER", "gcloud", "project_number"};
    static const config_var GCLOUD_SECRET_MANAGER_KEY_NAME = {"GCLOUD_SECRET_MANAGER_KEY_NAME", "secretmanager", "key_name"};
    static const config_var GCLOUD_LOCATION_ID = {"GCLOUD_LOCATION_ID", "gcloud", "location_id"};
    static const config_var GCLOUD_KMS_RING = {"GCLOUD_KMS_RING", "kms", "ring"};
    static const config_var GCLOUD_CRYPTO_KEY = {"GCLOUD_CRYPTO_KEY", "kms", "crypto_key"};

    static const config_var HASHICORP_API_HCP_CLIENT_ID = {"HASHICORP_API_HCP_CLIENT_ID", "hashicorp_api", "hcp_client_id"};
    static const config_var HASHICORP_API_HCP_CLIENT_SECRET = {"HASHICORP_API_HCP_CLIENT_SECRET", "hashicorp_api", "hcp_client_secret"};
    static const config_var HASHICORP_API_ORGANIZATION_ID = {"HASHICORP_API_ORGANIZATION_ID", "hashicorp_api", "organization_id"};
    static const config_var HASHICORP_API_PROJECT_ID = {"HASHICORP_API_PROJECT_ID", "hashicorp_api", "project_id"};
    static const config_var HASHICORP_API_APP_NAME = {"HASHICORP_API_APP_NAME", "hashicorp_api", "app_name"};
    static const config_var HASHICORP_API_SECRET_NAME = {"HASHICORP_API_SECRET_NAME", "hashicorp_api", "secret_name"};

    static const config_var HASHICORP_CONTAINER_TOKEN = {"HASHICORP_CONTAINER_TOKEN", "hashicorp_container", "token"};
    static const config_var HASHICORP_CONTAINER_URL = {"HASHICORP_CONTAINER_URL", "hashicorp_container", "url"};
    static const config_var HASHICORP_CONTAINER_PATH = {"HASHICORP_CONTAINER_PATH", "hashicorp_container", "path"};
    static const config_var HASHICORP_CONTAINER_MOUNT_POINT = {"HASHICORP_CONTAINER_MOUNT_POINT", "hashicorp_container", "mount_point"};
    static const config_var HASHICORP_CONTAINER_KEY_NAME = {"HASHICORP_CONTAINER_KEY_NAME", "hashicorp_container", "key_name"};
    
    struct chacha20_poly1305_encrypted_data {
        size_t data_len;
        unsigned char* data;
        unsigned char nonce[24];
        unsigned char mac[16];
    };

    /** Parse the hex string into bytes (uint8_t or std::byte). Ignores whitespace. */
    template <typename Byte = uint8_t>
    std::vector<Byte> ParseHex(std::string_view str);
    
    std::string key_to_string(const unsigned char* key, size_t keylen);

    void initialize_encrypted_data(chacha20_poly1305_encrypted_data& encrypted_data, size_t data_len);

    void fill_random_bytes(unsigned char* buffer, size_t buffer_len, const std::string& purpose);

    uint16_t getServerPort();

    std::string getStringConfigVar(const std::string& env_var, const std::string& toml_var_1, const std::string& toml_var_2);

    std::string getStringConfigVar(const config_var& config_variable);

} // namespace utils

#endif // UTILS_H
