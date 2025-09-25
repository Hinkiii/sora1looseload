#include "pch.h"
#include "detours.h"
#include <windows.h>
#include <thread>
#include <cstdio>
#include <xinput.h>
#include <string>
#include <psapi.h>

char g_gameDir[MAX_PATH] = {};

FILE* gLogFile = nullptr;


void InitLogFile() {
    if (fopen_s(&gLogFile, "console.log", "w") == 0 && gLogFile) {
        fprintf(gLogFile, "---- Log Started ----\n");
        fflush(gLogFile);
    }
}

uintptr_t FindPattern(uintptr_t base, DWORD size, const char* pattern, const char* mask) {
    size_t patternLength = strlen(mask);
    for (uintptr_t i = 0; i < size - patternLength; i++) {
        bool found = true;
        for (uintptr_t j = 0; j < patternLength; j++) {
            if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j)) {
                found = false;
                break;
            }
        }
        if (found) {
            return base + i;
        }
    }
    return 0;
}

void Log(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    buf[sizeof(buf) - 1] = '\0';
    va_end(args);

    printf("%s\n", buf);
    if (gLogFile) {
        fprintf(gLogFile, "%s\n", buf);
        fflush(gLogFile);
    }
}

bool FileExistsOnDisk(const char* path) {
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}



typedef __int64(__fastcall* InitialFileCheck_t)(__int64 a1, const char* a2, unsigned int a3, unsigned int a4, unsigned __int16 a5);
InitialFileCheck_t oInitialFileCheck = nullptr;
typedef __int64(__fastcall* FallbackLoader_t)(uintptr_t obj, char* file, unsigned int a3, unsigned __int16 a5);

__int64 __fastcall InitialFileCheck(__int64 a1, const char* a2, unsigned int a3, unsigned int a4, unsigned __int16 a5)
{
    if (!a2)
        return oInitialFileCheck(a1, a2, a3, a4, a5);

    size_t len = strlen(a2);
    if (len >= 4 && _stricmp(a2 + len - 4, ".pac") == 0)
        return oInitialFileCheck(a1, a2, a3, a4, a5);

    static thread_local char safeFullPath[MAX_PATH];
    const char* finalPathToLoad = a2;

    char fullPathToCheck[MAX_PATH] = {};
    //Log(a2);

    if (a2[1] != ':' && a2[0] != '\\' && a2[0] != '/')
    {
        snprintf(fullPathToCheck, MAX_PATH, "%s%s%s",
            g_gameDir,
            (g_gameDir[strlen(g_gameDir) - 1] == '\\' || g_gameDir[strlen(g_gameDir) - 1] == '/') ? "" : "\\",
            a2);

        for (char* p = fullPathToCheck; *p; ++p)
            if (*p == '/')
                *p = '\\';

        Log("[MOD] Checking if loose file exists: %s", fullPathToCheck);
        if (FileExistsOnDisk(fullPathToCheck))
        {
            Log("[MOD] Loose file FOUND. Overriding asset '%s' with '%s'", a2, fullPathToCheck);
            strncpy_s(safeFullPath, fullPathToCheck, sizeof(safeFullPath) - 1);
            finalPathToLoad = safeFullPath;
        }
    }

    __int64 ret = oInitialFileCheck(a1, finalPathToLoad, a3, a4, a5);
    return ret;
}

typedef void(__fastcall* DebugLogger_t)(int a1, __int64 a2, __int64 a3, const char* a4, ...);
DebugLogger_t oDebugLogger = nullptr;

void __fastcall DebugLogger(int a1, __int64 a2, __int64 a3, const char* a4, ...)
{
    if (!a4) return;

    char buffer[4096] = { 0 };
    va_list va;
    va_start(va, a4);
    vsnprintf(buffer, sizeof(buffer), a4, va);
    va_end(va);

    bool looksUTF16 = false;
    size_t len = strlen(buffer);
    if (len >= 4) {
        int zeros = 0, pairs = 0;
        for (size_t i = 1; i < len; i += 2, ++pairs)
            if (buffer[i] == '\0') zeros++;
        if (pairs > 0 && (zeros * 100 / pairs) > 70) looksUTF16 = true;
    }

    if (gLogFile) {
        if (looksUTF16) {
            int wideLen = (int)(len / 2);
            const wchar_t* wide = reinterpret_cast<const wchar_t*>(buffer);
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wide, wideLen, NULL, 0, NULL, NULL);
            if (utf8Len > 0) {
                std::string utf8(utf8Len, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wide, wideLen, &utf8[0], utf8Len, NULL, NULL);
                fprintf(gLogFile, "[LOG] %s\n", utf8.c_str());
            }
        }
        else {
            fprintf(gLogFile, "[LOG] %s\n", buffer);
        }
        fflush(gLogFile);
    }
}

typedef __int64(__fastcall* AssetLoader_t)(__int64 a1, const char* a2, unsigned int a3, unsigned int a4);
AssetLoader_t oAssetLoader = nullptr;

__int64 __fastcall AssetLoader(__int64 a1, char* a2, unsigned int a3, unsigned int a4) {
    Log("Asset requested: %s", a2 ? a2 : "(null)");
    return oAssetLoader(a1, a2, a3, a4);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        GetModuleFileNameA(NULL, g_gameDir, MAX_PATH);
        char* lastSlash = strrchr(g_gameDir, '\\');
        if (lastSlash) {
            *(lastSlash + 1) = '\0'; // we just need dir not the exe path
        }

        std::thread([hModule] {
            InitLogFile();

            uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
            if (!base) {
                Log("Failed to get module handle. (Somehow??)");
                return;
            }

            MODULEINFO moduleInfo;
            GetModuleInformation(GetCurrentProcess(), (HMODULE)base, &moduleInfo, sizeof(MODULEINFO));
            DWORD moduleSize = moduleInfo.SizeOfImage;

            // --- Signatures ---
            const char* assetLoaderSig = "\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\x98";
            const char* assetLoaderMask = "xxxxxxxxxxxxxxxxxx";

            const char* initialFileCheckSig_GLB = "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x8D\xAC\x24\x90\xFC\xFF\xFF";
            const char* initialFileCheckMask_GLB = "xxxxxxxxxxxxxxxxxxxx";

            const char* initialFileCheckSig_CLE = "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x81\xEC\x60\x02\x00\x00";
            const char* initialFileCheckMask_CLE = "xxxxxxxxxxxxxxxxxxx";

            const char* debugLoggerSig = "\x83\xF9\x02\x0F\x8C\x82\x00\x00\x00\x4C\x89\x4C\x24\x20\x53\x57";
            const char* debugLoggerMask = "xxxxxxxxxxxxxxxx";

            // --- Scanning ---
            Log("Scanning for signatures...");
            uintptr_t assetLoaderAddr = FindPattern(base, moduleSize, assetLoaderSig, assetLoaderMask);
            uintptr_t debugLoggerAddr = FindPattern(base, moduleSize, debugLoggerSig, debugLoggerMask);

            uintptr_t initialFileCheckAddr = FindPattern(base, moduleSize, initialFileCheckSig_GLB, initialFileCheckMask_GLB);

            if (!initialFileCheckAddr) {
                Log("Global signature not found. Scanning for CLE...");
                initialFileCheckAddr = FindPattern(base, moduleSize, initialFileCheckSig_CLE, initialFileCheckMask_CLE);
            }

            // --- Validation ---
            if (!assetLoaderAddr || !initialFileCheckAddr || !debugLoggerAddr) {
                if (!assetLoaderAddr) Log("AssetLoader signature not found!");
                if (!initialFileCheckAddr) Log("InitialFileCheck signature not found!");
                if (!debugLoggerAddr) Log("DebugLogger signature not found!");
                Log("Aborting due to missing signatures.");
                return;
            }

            Log("Found AssetLoader at: %p (offset: 0x%zX)", (void*)assetLoaderAddr, assetLoaderAddr - base);
            Log("Found InitialFileCheck at: %p (offset: 0x%zX)", (void*)initialFileCheckAddr, initialFileCheckAddr - base);
            Log("Found DebugLogger at: %p (offset: 0x%zX)", (void*)debugLoggerAddr, debugLoggerAddr - base);

            oAssetLoader = (AssetLoader_t)assetLoaderAddr;
            oInitialFileCheck = (InitialFileCheck_t)initialFileCheckAddr;
            oDebugLogger = (DebugLogger_t)debugLoggerAddr;

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach((void**)&oAssetLoader, AssetLoader);
            DetourAttach((void**)&oInitialFileCheck, InitialFileCheck);
            DetourAttach((void**)&oDebugLogger, DebugLogger);
            DetourTransactionCommit();

            Log("All detours attached successfully.");

            }).detach();
    }
    return TRUE;
}
