#include "pch.h"

#include "WinTrust_hook.h"

// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
LONG WINAPI WinVerifyTrust_hook(HWND hwnd, GUID* pgActionID, LPVOID pWVTData) {
    static auto file_handle
        = CreateFileW(ORIGINAL_CHROME_ELF_DLL, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    static WINTRUST_FILE_INFO FileInfo = {
        .cbStruct      = sizeof(WINTRUST_FILE_INFO_),
        .pcwszFilePath = ORIGINAL_CHROME_ELF_DLL,
        .hFile         = file_handle,
    };
    const auto WintrustData = reinterpret_cast<WINTRUST_DATA*>(pWVTData);
    auto pFileInfo          = WintrustData->pFile;

    wchar_t temp_buffer[MAX_PATH] = { 0 };
    wchar_t* file_name            = nullptr;

    const auto length = GetFullPathNameW(pFileInfo->pcwszFilePath, MAX_PATH, temp_buffer, &file_name);

    if (length == 0 || length >= MAX_PATH || file_name == nullptr) {
        return WinVerifyTrust(hwnd, pgActionID, pWVTData);
    }

    if (0 == lstrcmpiW(L"chrome_elf.dll", file_name)) {
        if (file_handle != INVALID_HANDLE_VALUE) {
            WintrustData->pFile = &FileInfo;
            const auto result   = WinVerifyTrust(hwnd, pgActionID, pWVTData);
            WintrustData->pFile = pFileInfo;
            return result;
        }
    }
    return WinVerifyTrust(hwnd, pgActionID, pWVTData);
}

static HMODULE GetVersionModule() noexcept {
    static HMODULE h = []() {
        auto mod = GetModuleHandleW(L"version.dll");
        if (!mod) { mod = LoadLibraryW(L"version.dll"); }
        return mod;
    }();
    return h;
}

DWORD WINAPI GetFileVersionInfoSizeW_hook(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    static const auto orig = reinterpret_cast<decltype(&GetFileVersionInfoSizeW)>(
        GetProcAddress(GetVersionModule(), "GetFileVersionInfoSizeW"));

    if (lptstrFilename && wcsstr(lptstrFilename, L"chrome_elf.dll")) { lptstrFilename = ORIGINAL_CHROME_ELF_DLL; }
    return orig ? orig(lptstrFilename, lpdwHandle) : 0;
}

BOOL WINAPI GetFileVersionInfoW_hook(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    static const auto orig
        = reinterpret_cast<decltype(&GetFileVersionInfoW)>(GetProcAddress(GetVersionModule(), "GetFileVersionInfoW"));

    if (lptstrFilename && wcsstr(lptstrFilename, L"chrome_elf.dll")) { lptstrFilename = ORIGINAL_CHROME_ELF_DLL; }
    return orig ? orig(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI GetFileVersionInfoSizeA_hook(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    static const auto orig = reinterpret_cast<decltype(&GetFileVersionInfoSizeA)>(
        GetProcAddress(GetVersionModule(), "GetFileVersionInfoSizeA"));

    if (lptstrFilename && strstr(lptstrFilename, "chrome_elf.dll")) { lptstrFilename = ORIGINAL_CHROME_ELF_DLLA; }
    return orig ? orig(lptstrFilename, lpdwHandle) : 0;
}

BOOL WINAPI GetFileVersionInfoA_hook(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    static const auto orig
        = reinterpret_cast<decltype(&GetFileVersionInfoA)>(GetProcAddress(GetVersionModule(), "GetFileVersionInfoA"));

    if (lptstrFilename && strstr(lptstrFilename, "chrome_elf.dll")) { lptstrFilename = ORIGINAL_CHROME_ELF_DLLA; }
    return orig ? orig(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI GetFileVersionInfoSizeExW_hook(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    static const auto orig = reinterpret_cast<decltype(&GetFileVersionInfoSizeExW)>(
        GetProcAddress(GetVersionModule(), "GetFileVersionInfoSizeExW"));

    if (lpwstrFilename && wcsstr(lpwstrFilename, L"chrome_elf.dll")) { lpwstrFilename = ORIGINAL_CHROME_ELF_DLL; }
    return orig ? orig(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

BOOL WINAPI GetFileVersionInfoExW_hook(
    DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    static const auto orig = reinterpret_cast<decltype(&GetFileVersionInfoExW)>(
        GetProcAddress(GetVersionModule(), "GetFileVersionInfoExW"));

    if (lpwstrFilename && wcsstr(lpwstrFilename, L"chrome_elf.dll")) { lpwstrFilename = ORIGINAL_CHROME_ELF_DLL; }
    return orig ? orig(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}
