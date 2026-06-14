#include "pch.h"

#include "css_cosmetic.h"
#include "loader.h"
#include "log_thread.h"
#include "pattern.h"

#include <array>
#include <string_view>

void vbar_noop(const char* file_name, void* buffer, std::size_t bufferSize) noexcept {}

static inline bool is_homepage_vbar_hide() noexcept {
    auto result = GetPrivateProfileIntA("Homepage_vbar", "Enable", 0, CONFIG_FILEA);
    return 0 != result;
}

static inline void do_hide_vbar(const char* file_name, void* buffer, std::size_t bufferSize) noexcept {
    std::array<char, 2048> vbar_buffer {};
    std::size_t len = strnlen_s(file_name, 128);
    if (len < 4 || 0 != lstrcmpiA(file_name + len - 4, ".css")) { return; }

    Modify modify {};

    const auto signature_raw_length = GetPrivateProfileStringA(
        "Homepage_vbar", "Signature", "", vbar_buffer.data(), vbar_buffer.size(), CONFIG_FILEA);

    const auto signature_hex_size
        = parse_signaure(vbar_buffer.data(), signature_raw_length, modify.signature, modify.mask, vbar_buffer.size());

    if (SIZE_MAX == signature_hex_size) {
        log_debug("do_hide_vbar: parse_signaure limit exceed.");
        return;
    }

    modify.mask[signature_hex_size] = '\0';

    modify.offset = GetPrivateProfileIntA("Homepage_vbar", "Offset", 0, CONFIG_FILEA);

    const auto value_raw_length
        = GetPrivateProfileStringA("Homepage_vbar", "Value", "", vbar_buffer.data(), vbar_buffer.size(), CONFIG_FILEA);

    modify.patch_size = parse_hex(vbar_buffer.data(), value_raw_length, modify.value, vbar_buffer.size());

    if (SIZE_MAX == modify.patch_size) {
        log_debug("do_hide_vbar: parse_hex limit exceed.");
        return;
    }

    if (modify.patch_size > signature_hex_size) {
        log_debug("do_hide_vbar: patch_size > signature_hex_size.");
        return;
    }

    const auto address
        = FindPattern(std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(buffer), bufferSize),
            std::span<const std::uint8_t>(modify.signature, sizeof(modify.signature)), std::string_view(modify.mask));

    std::array<char, SHARED_BUFFER_SIZE> temp_log_buffer {};

    if (nullptr == address) {
        _snprintf_s(
            temp_log_buffer.data(), SHARED_BUFFER_SIZE, _TRUNCATE, "do_hide_vbar: %s FindPattern failed.", file_name);
        log_debug(temp_log_buffer.data());
        return;
    }

    if (buffer != address) {
        // it the first in the css file...
        return;
    }
    if (address) { memcpy(address + modify.offset, modify.value, modify.patch_size); }
    _snprintf_s(temp_log_buffer.data(), SHARED_BUFFER_SIZE, _TRUNCATE, "do_hide_vbar: %s patched.", file_name);
    log_info(temp_log_buffer.data());
}

void modify_css_init() noexcept {
    if (true == is_homepage_vbar_hide()) { css_hide_vbar = do_hide_vbar; }
}
