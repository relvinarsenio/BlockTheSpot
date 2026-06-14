#pragma once
#include <cstdint>

template <typename T> inline T get_funct_t(void* base, std::size_t offset) {
    return *reinterpret_cast<T*>(reinterpret_cast<std::uintptr_t>(base) + offset);
}

template <typename T> inline void overwrite_funct_t(void* base, std::size_t offset, T replacement) {
    auto slot = reinterpret_cast<void**>(reinterpret_cast<std::uintptr_t>(base) + offset);
    DWORD old = 0;
    VirtualProtect(slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
    *slot = reinterpret_cast<void*>(replacement);
    VirtualProtect(slot, sizeof(void*), old, &old);
}