#ifndef FILESYSTEM_KEY_MANAGER_H
#define FILESYSTEM_KEY_MANAGER_H

#include <string>
#include <vector>

namespace filesystem_key_manager {
    std::vector<uint8_t> get_seed();
    bool embedded_storage_needs_initialization();
} // namespace key_manager

#endif // FILESYSTEM_KEY_MANAGER_H
