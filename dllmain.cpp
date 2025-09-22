#include "pch.h"
#include "detours.h"
#include <windows.h>
#include <thread>
#include <cstdio>
#include <xinput.h>
#include <string>

char g_gameDir[MAX_PATH] = {};

FILE* gLogFile = nullptr;


void InitLogFile() {
    if (fopen_s(&gLogFile, "console.log", "w") == 0 && gLogFile) {
        fprintf(gLogFile, "---- Log Started ----\n");
        fflush(gLogFile);
    }
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

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourTransactionCommit();

            uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
            uintptr_t target = base + 0x4988F0;
            const unsigned char pattern[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55 };

            Log("Waiting for function at %p to match prologue...", (void*)target);
            for (;;) {
                if (memcmp((void*)target, pattern, sizeof(pattern)) == 0) break;
                Sleep(10);
            }
            Log("Function prologue matched, attaching detours.");

            oAssetLoader = (AssetLoader_t)target;
            oInitialFileCheck = (InitialFileCheck_t)(base + 0x51BF50);
            oDebugLogger = (DebugLogger_t)(base + 0x452990);

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach((void**)&oAssetLoader, AssetLoader);
            DetourAttach((void**)&oInitialFileCheck, InitialFileCheck);
            DetourAttach((void**)&oDebugLogger, DebugLogger);
            DetourTransactionCommit();

            }).detach();
    }
    return TRUE;
}
