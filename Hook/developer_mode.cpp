#include "pch.h"

#include "developer_mode.h"
#include "loader.h"
#include "log_thread.h"
#include "memory.h"
#include "pattern.h"

#include <array>

static inline bool is_developer_mode() noexcept {
    auto result = GetPrivateProfileIntA("Developer", "Enable", 0, CONFIG_FILEA);
    return 0 != result;
}

static inline void do_hook_developer(HMODULE spotify_dll_handle) noexcept {
    Modify modify {};
    std::array<char, SHARED_BUFFER_SIZE> temp_buffer {};

    const auto signature_raw_length
        = GetPrivateProfileStringA("Developer", "Signature", "", temp_buffer.data(), SHARED_BUFFER_SIZE, CONFIG_FILEA);

    const auto signature_hex_size
        = parse_signaure(temp_buffer.data(), signature_raw_length, modify.signature, modify.mask, SHARED_BUFFER_SIZE);

    if (SIZE_MAX == signature_hex_size) {
        log_debug("do_hook_developer: parse_signaure limit exceed.");
        return;
    }

    modify.mask[signature_hex_size] = '\0';

    modify.offset = GetPrivateProfileIntA("Developer", "Offset", 0, CONFIG_FILEA);

    const auto value_raw_length
        = GetPrivateProfileStringA("Developer", "Value", "", temp_buffer.data(), SHARED_BUFFER_SIZE, CONFIG_FILEA);

    modify.patch_size = parse_hex(temp_buffer.data(), value_raw_length, modify.value, SHARED_BUFFER_SIZE);

    if (SIZE_MAX == modify.patch_size) {
        log_debug("do_hook_developer: parse_hex limit exceed.");
        return;
    }

    if (modify.patch_size > signature_hex_size) {
        log_debug("do_hook_developer: patch_size > signature_hex_size.");
        return;
    }

    DLL_section dll {};
    if (false == get_text_section(spotify_dll_handle, &dll)) {
        log_debug("do_hook_developer: get_text_section failed.");
        return;
    }

    const auto address = FindPattern(std::span<const std::uint8_t>(dll.address, dll.size),
        std::span<const std::uint8_t>(modify.signature, SHARED_BUFFER_SIZE), std::string_view(modify.mask));

    if (nullptr == address) {
        log_debug("do_hook_developer: FindPattern failed.");
        return;
    }

    const auto start = address + modify.offset + modify.patch_size;
    const auto end   = dll.address + dll.size;
    if (start > end) {
        log_debug("do_hook_developer: patch overflow.");
        return;
    }

    if (address) {
        patch_instruction(reinterpret_cast<LPVOID*>(address + modify.offset), modify.value, modify.patch_size);
        log_info("do_hook_developer: patch applied.");
        return;
    }
    log_debug("do_hook_developer: fail to patch.");
}

void hook_developer_mode(HMODULE spotify_dll_handle) noexcept {
    if (true == is_developer_mode()) { do_hook_developer(spotify_dll_handle); }
}
