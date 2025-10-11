#include "pch.h"
#include "detours.h"
#include <windows.h>
#include <thread>
#include <cstdio>
#include <xinput.h>
#include <string>
#include <psapi.h>
#include <atomic>
#include <mutex>
#include <share.h>
#include <cstdarg>

char g_gameDir[MAX_PATH] = {};
FILE* gLogFile = nullptr;
std::atomic<unsigned __int16> g_currentLocale = 0;
std::string g_localeSuffix;
std::mutex g_localeMutex;

void InitLogFile() {
    gLogFile = _fsopen("console.log", "w", _SH_DENYNO);
    if (gLogFile) {
        fprintf(gLogFile, "---- Log Started ----\n");
        fflush(gLogFile);
    }
}

void Log(const char* fmt, ...) {
    char buf[2048];
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
        if (found)
            return base + i;
    }
    return 0;
}

typedef __int64(__fastcall* InitialFileCheck_t)(__int64 a1, const char* a2, unsigned int a3, unsigned int a4, unsigned __int16 a5);
typedef void(__fastcall* DebugLogger_t)(int a1, __int64 a2, __int64 a3, const char* a4, ...);
typedef void(__fastcall* LocaleHandler_t)(__int64 mgr, char* dest, unsigned __int16* locale, char* src, int zero);

InitialFileCheck_t oInitialFileCheck = nullptr;
DebugLogger_t oDebugLogger = nullptr;
LocaleHandler_t oLocaleHandler = nullptr;

__int64 g_localeMgr = 0;

__int64 __fastcall InitialFileCheck(__int64 a1, const char* a2, unsigned int a3, unsigned int a4, unsigned __int16 a5)
{
    if (!a2)
        return oInitialFileCheck(a1, a2, a3, a4, a5);

    size_t len = strlen(a2);
    if (len >= 4 && _stricmp(a2 + len - 4, ".pac") == 0)
        return oInitialFileCheck(a1, a2, a3, a4, a5);

    static thread_local char safeFullPath[MAX_PATH];
    static thread_local char localizedPath[MAX_PATH];
    const char* finalPath = a2;

    size_t gameDirLen = 0;
    bool gameDirHasSlash = false;
    if (g_gameDir[0]) {
        gameDirLen = strnlen_s(g_gameDir, MAX_PATH);
        if (gameDirLen > 0) {
            char last = g_gameDir[gameDirLen - 1];
            gameDirHasSlash = (last == '\\' || last == '/');
        }
    }

    auto normalize_to_backslashes = [](char* s) {
        for (; *s; ++s) if (*s == '/') *s = '\\';
        };

    bool hasLocaleSuffix = false;

    if (oLocaleHandler && g_localeMgr)
    {
        localizedPath[0] = '\0';
        oLocaleHandler(g_localeMgr, localizedPath, (unsigned __int16*)&a5, (char*)a2, 0);

        if (localizedPath[0])
        {
            char srcNorm[MAX_PATH];
            char destNorm[MAX_PATH];
            strncpy_s(srcNorm, sizeof(srcNorm), a2, _TRUNCATE);
            strncpy_s(destNorm, sizeof(destNorm), localizedPath, _TRUNCATE);

            for (char* p = srcNorm; *p; ++p) if (*p == '\\') *p = '/';
            for (char* p = destNorm; *p; ++p) if (*p == '\\') *p = '/';

            const char* slashSrc = strchr(srcNorm, '/');
            const char* slashDest = strchr(destNorm, '/');

            if (slashSrc && slashDest)
            {
                size_t srcDirLen = (size_t)(slashSrc - srcNorm);
                size_t destDirLen = (size_t)(slashDest - destNorm);
                if (destDirLen > srcDirLen && strncmp(destNorm, srcNorm, srcDirLen) == 0) {
                    size_t suffixLen = destDirLen - srcDirLen;
                    if (suffixLen < MAX_PATH) {
                        char currentSuffix[MAX_PATH] = {};
                        strncpy_s(currentSuffix, sizeof(currentSuffix), destNorm + srcDirLen, suffixLen);
                        if (strlen(currentSuffix) > 0) {
                            std::lock_guard<std::mutex> lock(g_localeMutex);
                            g_localeSuffix = currentSuffix;
                            hasLocaleSuffix = true;
                            Log("[MOD] >>> Detected locale suffix: '%s'", currentSuffix);
                        }
                    }
                }
            }

            if (hasLocaleSuffix)
            {
                char fullPath[MAX_PATH];
                if (gameDirLen && gameDirHasSlash)
                    snprintf(fullPath, sizeof(fullPath), "%s%s", g_gameDir, localizedPath);
                else if (gameDirLen)
                    snprintf(fullPath, sizeof(fullPath), "%s\\%s", g_gameDir, localizedPath);
                else
                    snprintf(fullPath, sizeof(fullPath), "%s", localizedPath);

                normalize_to_backslashes(fullPath);

                Log("[MOD] Checking localized loose file: '%s'", fullPath);

                if (FileExistsOnDisk(fullPath))
                {
                    Log("[MOD] Found localized loose file! Using '%s'", fullPath);
                    strncpy_s(safeFullPath, sizeof(safeFullPath), fullPath, _TRUNCATE);
                    finalPath = safeFullPath;
                }
                else
                {
                    finalPath = localizedPath;
                }
            }
        }
        else
        {
            Log("[DEBUG] LocaleHandler returned empty path for '%s'", a2);
        }
    }

    if (finalPath == a2)
    {
        char fullPathToCheck[MAX_PATH];
        if (gameDirLen && gameDirHasSlash)
            snprintf(fullPathToCheck, sizeof(fullPathToCheck), "%s%s", g_gameDir, a2);
        else if (gameDirLen)
            snprintf(fullPathToCheck, sizeof(fullPathToCheck), "%s\\%s", g_gameDir, a2);
        else
            snprintf(fullPathToCheck, sizeof(fullPathToCheck), "%s", a2);

        normalize_to_backslashes(fullPathToCheck);

        Log("[MOD] Checking standard loose file: '%s'", fullPathToCheck);

        if (FileExistsOnDisk(fullPathToCheck))
        {
            Log("[MOD] Standard loose file found: '%s'", fullPathToCheck);
            strncpy_s(safeFullPath, sizeof(safeFullPath), fullPathToCheck, _TRUNCATE);
            finalPath = safeFullPath;
        }
    }

    Log("[MOD] Passing '%s' to original InitialFileCheck", finalPath);
    return oInitialFileCheck(a1, finalPath, a3, a4, a5);
}



void __fastcall DebugLogger(int a1, __int64 a2, __int64 a3, const char* a4, ...) {
    if (!a4) return;
    char buffer[4096] = { 0 };
    va_list va;
    va_start(va, a4);
    vsnprintf(buffer, sizeof(buffer), a4, va);
    va_end(va);
    if (gLogFile) {
        fprintf(gLogFile, "[LOG] %s\n", buffer);
        fflush(gLogFile);
    }
}

void __fastcall hkLocaleHandler(__int64 mgr, char* dest, unsigned __int16* locale, char* src, int zero) {
    unsigned __int16 loc = locale ? *locale : 0;
    g_currentLocale.store(loc);
    g_localeMgr = mgr;
    oLocaleHandler(mgr, dest, locale, src, zero);

    if (src && dest && dest[0] != '\0') {
        char s_src[MAX_PATH];
        char s_dest[MAX_PATH];
        strncpy_s(s_src, sizeof(s_src), src, _TRUNCATE);
        strncpy_s(s_dest, sizeof(s_dest), dest, _TRUNCATE);
        for (char* p = s_src; *p; ++p) if (*p == '\\') *p = '/';
        for (char* p = s_dest; *p; ++p) if (*p == '\\') *p = '/';

        const char* firstSlashSrc = strchr(s_src, '/');
        const char* firstSlashDest = strchr(s_dest, '/');

        if (firstSlashSrc && firstSlashDest) {
            size_t srcDirLen = (size_t)(firstSlashSrc - s_src);
            size_t destDirLen = (size_t)(firstSlashDest - s_dest);
            if (destDirLen > srcDirLen && strncmp(s_dest, s_src, srcDirLen) == 0) {
                size_t suffixLen = destDirLen - srcDirLen;
                if (suffixLen < MAX_PATH) {
                    char currentSuffix[MAX_PATH] = {};
                    strncpy_s(currentSuffix, sizeof(currentSuffix), s_dest + srcDirLen, suffixLen);
                    {
                        std::lock_guard<std::mutex> lock(g_localeMutex);
                        g_localeSuffix = currentSuffix;
                    }
                    Log("[MOD] >>> Detected locale suffix: '%s'", currentSuffix);
                }
            }
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        GetModuleFileNameA(NULL, g_gameDir, MAX_PATH);
        char* lastSlash = strrchr(g_gameDir, '\\');
        if (lastSlash)
            *(lastSlash + 1) = '\0';

        std::thread([hModule] {
            InitLogFile();

            uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
            if (!base) {
                Log("Failed to get module handle.");
                return;
            }

            MODULEINFO moduleInfo;
            GetModuleInformation(GetCurrentProcess(), (HMODULE)base, &moduleInfo, sizeof(MODULEINFO));
            DWORD moduleSize = moduleInfo.SizeOfImage;

            const char* initialFileCheckSig_GLB = "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x8D\xAC\x24\x90\xFC\xFF\xFF";
            const char* initialFileCheckMask_GLB = "xxxxxxxxxxxxxxxxxxxx";
            const char* initialFileCheckSig_CLE = "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x81\xEC\x60\x02\x00\x00";
            const char* initialFileCheckMask_CLE = "xxxxxxxxxxxxxxxxxxx";
            const char* debugLoggerSig = "\x83\xF9\x02\x0F\x8C\x82\x00\x00\x00\x4C\x89\x4C\x24\x20\x53\x57";
            const char* debugLoggerMask = "xxxxxxxxxxxxxxxx";
            const char* localeHandlerSig = "\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\xA8\xFE\xFF\xFF";
            const char* localeHandlerMask = "xxxxxxxxxxxxxxxxxxxxx";

            Log("Scanning for signatures...");
            uintptr_t debugLoggerAddr = FindPattern(base, moduleSize, debugLoggerSig, debugLoggerMask);
            uintptr_t initialFileCheckAddr = FindPattern(base, moduleSize, initialFileCheckSig_GLB, initialFileCheckMask_GLB);
            if (!initialFileCheckAddr)
                initialFileCheckAddr = FindPattern(base, moduleSize, initialFileCheckSig_CLE, initialFileCheckMask_CLE);
            uintptr_t localeHandlerAddr = FindPattern(base, moduleSize, localeHandlerSig, localeHandlerMask);

            if (!initialFileCheckAddr || !debugLoggerAddr || !localeHandlerAddr) {
                Log("Aborting due to missing signatures.");
                Log("InitialFileCheck: %p, DebugLogger: %p, LocaleHandler: %p", (void*)initialFileCheckAddr, (void*)debugLoggerAddr, (void*)localeHandlerAddr);
                return;
            }

            oInitialFileCheck = (InitialFileCheck_t)initialFileCheckAddr;
            oDebugLogger = (DebugLogger_t)debugLoggerAddr;
            oLocaleHandler = (LocaleHandler_t)localeHandlerAddr;

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach((void**)&oInitialFileCheck, InitialFileCheck);
            DetourAttach((void**)&oDebugLogger, DebugLogger);
            DetourAttach((void**)&oLocaleHandler, hkLocaleHandler);
            DetourTransactionCommit();

            Log("All detours attached successfully.");
            }).detach();
    }
    return TRUE;
}
