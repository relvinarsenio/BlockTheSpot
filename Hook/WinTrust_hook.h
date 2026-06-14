#pragma once
#include "loader.h"

#include <WinTrust.h>
#pragma comment(lib, "Wintrust.lib")

using WinVerifyTrust_t = LONG(WINAPI*)(HWND, GUID*, LPVOID);
LONG WINAPI WinVerifyTrust_hook(HWND hwnd, GUID* pgActionID, LPVOID pWVTData);

DWORD WINAPI GetFileVersionInfoSizeW_hook(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
BOOL WINAPI GetFileVersionInfoW_hook(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DWORD WINAPI GetFileVersionInfoSizeA_hook(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
BOOL WINAPI GetFileVersionInfoA_hook(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DWORD WINAPI GetFileVersionInfoSizeExW_hook(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle);
BOOL WINAPI GetFileVersionInfoExW_hook(
    DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
// static WinVerifyTrust_t WinVerifyTrust_orig = nullptr;
