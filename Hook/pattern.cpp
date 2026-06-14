#include "pattern.h"

#include "pch.h"

#include <ranges>

struct Hex_table {
    std::uint8_t data[256];
};

static inline constexpr std::uint8_t hexchar_to_byte(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<std::uint8_t>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
        return static_cast<std::uint8_t>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
        return static_cast<std::uint8_t>(c - 'A' + 10);
    } else {
        return 0xFF;
    }
}

static consteval Hex_table make_hex_table() {
    Hex_table t {};

    for (int i : std::views::iota(0, 256)) {
        t.data[i] = hexchar_to_byte(static_cast<unsigned char>(i));
    }

    return t;
}

static inline constexpr Hex_table lookup_hex = make_hex_table();

static inline constexpr std::uint8_t hexchar(char c) {
    return lookup_hex.data[static_cast<unsigned char>(c)];
}

static constexpr std::uint8_t hex_pair(char hi, char lo) {
    std::uint8_t h = hexchar(hi);
    std::uint8_t l = hexchar(lo);
    return (h | l) == 0xFF ? 0xFF : static_cast<std::uint8_t>((h << 4) | l);
}

bool get_text_section(HMODULE module, DLL_section* const dll_section) noexcept {
    if (nullptr == dll_section || !module) { return false; }

    constexpr const char TEXT_STR[] = ".text";
    constexpr std::size_t TEXT_LEN  = ARRAYSIZE(TEXT_STR) - 1;
    static_assert(TEXT_LEN <= IMAGE_SIZEOF_SHORT_NAME, "PE section name too long");

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(module) + dos->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (0 == memcmp(section->Name, TEXT_STR, TEXT_LEN)) {
            dll_section->address = reinterpret_cast<std::uint8_t*>(module) + section->VirtualAddress;
            dll_section->size    = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

bool DataCompare(
    std::span<const std::uint8_t> data, std::span<const std::uint8_t> sig, std::string_view mask) noexcept {
    if (data.size() < sig.size() || sig.size() < mask.size()) { return false; }
    for (std::size_t i = 0; i < mask.size(); ++i) {
        if (mask[i] == 'x' && data[i] != sig[i]) { return false; }
    }
    return true;
}

std::uint8_t* FindPattern(
    std::span<const std::uint8_t> data, std::span<const std::uint8_t> sig, std::string_view mask) noexcept {
    if (data.size() < mask.size()) { return nullptr; }
    const std::size_t limit = data.size() - mask.size();
    for (std::size_t i : std::views::iota(0ULL, limit + 1)) {
        if (DataCompare(data.subspan(i), sig, mask)) { return const_cast<std::uint8_t*>(&data[i]); }
    }
    return nullptr;
}

std::size_t parse_signaure(
    const char* src, std::size_t src_len, std::uint8_t* out_bytes, char* out_mask, std::size_t limit) noexcept {
    std::size_t i   = 0;
    std::size_t out = 0;

    while (i < src_len) {
        char c = src[i];
        if (c == ' ' || c == '\t') {
            ++i;
            continue;
        }

        if (i + 1 < src_len && src[i] == '?' && src[i + 1] == '?') {
            if (out >= limit) { return SIZE_MAX; }

            out_bytes[out] = 0x00;
            out_mask[out]  = '?';
            ++out;
            i += 2;
            continue;
        }

        if (i + 1 >= src_len) { return SIZE_MAX; }

        const std::uint8_t b = hex_pair(src[i], src[i + 1]);
        if (b == 0xFF) { return SIZE_MAX; }

        if (out >= limit) { return SIZE_MAX; }

        out_bytes[out] = b;
        out_mask[out]  = 'x';
        ++out;
        i += 2;
    }

    return out;
}

std::size_t parse_hex(const char* src, std::size_t src_len, std::uint8_t* out_bytes, std::size_t out_cap) noexcept {
    std::size_t i   = 0;
    std::size_t out = 0;

    while (i < src_len) {
        char c = src[i];
        if (c == ' ' || c == '\t') {
            ++i;
            continue;
        }

        if (i + 1 >= src_len) { return SIZE_MAX; }

        const std::uint8_t b = hex_pair(src[i], src[i + 1]);
        if (b == 0xFF) { return SIZE_MAX; }

        if (out >= out_cap) { return SIZE_MAX; }

        out_bytes[out] = b;
        ++out;
        i += 2;
    }

    return out;
}
