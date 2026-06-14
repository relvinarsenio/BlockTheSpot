#include "pch.h"

#include "libcef_hook.h"
#include "IAT_hook.h"
#include "cef_url_hook.h"
#include "cef_zip_reader_hook.h"

static FARPROC WINAPI GetProcAddress_hook(HMODULE hModule, LPCSTR lpProcName) {
    if (!lpProcName || 0 == HIWORD(reinterpret_cast<std::uintptr_t>(lpProcName))) {
        return GetProcAddress_orig(hModule, lpProcName);
    }

    if (0 == lstrcmpiA(lpProcName, "cef_urlrequest_create")) {
        if (hModule == GetModuleHandleW(L"libcef.dll")) {
            return reinterpret_cast<FARPROC>(cef_urlrequest_create_stub);
        }
    }
    if (0 == lstrcmpiA(lpProcName, "cef_zip_reader_create")) {
        if (hModule == GetModuleHandleW(L"libcef.dll")) {
            return reinterpret_cast<FARPROC>(cef_zip_reader_create_stub);
        }
    }
    return GetProcAddress_orig(hModule, lpProcName);
}

// https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking
bool libcef_IAT_hook_GetProcAddress(HMODULE spotify_dll_handle) noexcept {
    if (!spotify_dll_handle) { return false; }

    if (nullptr == ImageDirectoryEntryToDataEx) {
        OutputDebugStringW(L"libcef_IAT_hook_GetProcAddress: ImageDirectoryEntryToDataEx is null.");
        return false;
    }

    ULONG size   = 0;
    auto imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ImageDirectoryEntryToDataEx(spotify_dll_handle,
        TRUE, // image is loaded in memory
        IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL));

    if (nullptr == imports) { return false; }

    for (; imports->Name; ++imports) {
        auto dll_name = reinterpret_cast<LPCSTR>(reinterpret_cast<std::uint8_t*>(spotify_dll_handle) + imports->Name);

        // GetProcAddress is in kernel32
        if (0 == lstrcmpiA(dll_name, "kernel32.dll")) {

            auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                reinterpret_cast<std::uint8_t*>(spotify_dll_handle) + imports->FirstThunk);

            for (; thunk->u1.Function; ++thunk) {
                auto func = reinterpret_cast<PROC*>(&thunk->u1.Function);

                if (*func == reinterpret_cast<PROC>(GetProcAddress)) {
                    DWORD oldProtect = 0;
                    VirtualProtect(func, sizeof(PROC), PAGE_READWRITE, &oldProtect);

                    GetProcAddress_orig = reinterpret_cast<GetProcAddress_t>(*func);
                    *func               = reinterpret_cast<PROC>(GetProcAddress_hook);

                    VirtualProtect(func, sizeof(PROC), oldProtect, &oldProtect);
                    return true;
                }
            }
        }
    }
    return false;
}