#pragma once
#include "loader.h"

struct DLL_section {
    std::uint32_t size;
    std::uint8_t* address;
};

struct Modify {
    std::uint8_t signature[SHARED_BUFFER_SIZE];
    char mask[SHARED_BUFFER_SIZE];
    std::uint32_t offset;
    std::uint8_t value[SHARED_BUFFER_SIZE];
    std::size_t patch_size;
};

#include <span>
#include <string_view>

// https://www.unknowncheats.me/forum/1064672-post23.html
bool DataCompare(std::span<const std::uint8_t> data, std::span<const std::uint8_t> sig, std::string_view mask) noexcept;
std::uint8_t* FindPattern(
    std::span<const std::uint8_t> data, std::span<const std::uint8_t> sig, std::string_view mask) noexcept;

bool get_text_section(HMODULE module, DLL_section* const dll_section) noexcept;

std::size_t parse_signaure(
    const char* src, std::size_t src_len, std::uint8_t* out_bytes, char* out_mask, std::size_t out_cap) noexcept;

std::size_t parse_hex(const char* src, std::size_t src_len, std::uint8_t* out_bytes, std::size_t out_cap) noexcept;
