#include "pch.h"
#pragma comment(linker, "/EXPORT:XInputEnable=XInputEnable,@5")
#pragma comment(linker, "/EXPORT:XInputGetAudioDeviceIds=XInputGetAudioDeviceIds,@10")
#pragma comment(linker, "/EXPORT:XInputGetBatteryInformation=XInputGetBatteryInformation,@7")
#pragma comment(linker, "/EXPORT:XInputGetCapabilities=XInputGetCapabilities,@4")
#pragma comment(linker, "/EXPORT:XInputGetKeystroke=XInputGetKeystroke,@8")
#pragma comment(linker, "/EXPORT:XInputGetState=XInputGetState,@2")
#pragma comment(linker, "/EXPORT:XInputSetState=XInputSetState,@3")

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    HINSTANCE s_instance = NULL;
    struct XINPUT_STATE {};
    struct XINPUT_CAPABILITIES {};
    struct XINPUT_BATTERY_INFORMATION {};
    struct XINPUT_KEYSTROKE {};

    typedef void (WINAPI* f_XInputEnable)(BOOL);
    typedef DWORD(WINAPI* f_XInputGetAudioDeviceIds)(DWORD, LPWSTR, UINT*, LPWSTR, UINT*);
    typedef DWORD(WINAPI* f_XInputGetBatteryInformation)(DWORD, BYTE, XINPUT_BATTERY_INFORMATION*);
    typedef DWORD(WINAPI* f_XInputGetCapabilities)(DWORD, DWORD, XINPUT_CAPABILITIES*);
    typedef DWORD(WINAPI* f_XInputGetKeystroke)(DWORD, DWORD, XINPUT_KEYSTROKE*);
    typedef DWORD(WINAPI* f_XInputGetState)(DWORD, XINPUT_STATE*);
    typedef DWORD(WINAPI* f_XInputSetState)(DWORD, void*);

    f_XInputEnable s_XInputEnable = NULL;
    f_XInputGetAudioDeviceIds s_XInputGetAudioDeviceIds = NULL;
    f_XInputGetBatteryInformation s_XInputGetBatteryInformation = NULL;
    f_XInputGetCapabilities s_XInputGetCapabilities = NULL;
    f_XInputGetKeystroke s_XInputGetKeystroke = NULL;
    f_XInputGetState s_XInputGetState = NULL;
    f_XInputSetState s_XInputSetState = NULL;

    void load()
    {
        WCHAR path[MAX_PATH];
        GetSystemDirectoryW(path, MAX_PATH);
        wcscat_s(path, L"\\XInput1_4.dll");
        s_instance = LoadLibraryW(path);

        if (!s_instance)
            return;

        s_XInputEnable = (f_XInputEnable)GetProcAddress(s_instance, "XInputEnable");
        s_XInputGetAudioDeviceIds = (f_XInputGetAudioDeviceIds)GetProcAddress(s_instance, "XInputGetAudioDeviceIds");
        s_XInputGetBatteryInformation = (f_XInputGetBatteryInformation)GetProcAddress(s_instance, "XInputGetBatteryInformation");
        s_XInputGetCapabilities = (f_XInputGetCapabilities)GetProcAddress(s_instance, "XInputGetCapabilities");
        s_XInputGetKeystroke = (f_XInputGetKeystroke)GetProcAddress(s_instance, "XInputGetKeystroke");
        s_XInputGetState = (f_XInputGetState)GetProcAddress(s_instance, "XInputGetState");
        s_XInputSetState = (f_XInputSetState)GetProcAddress(s_instance, "XInputSetState");
    }

    void WINAPI XInputEnable(BOOL enable)
    {
        if (!s_XInputEnable)
            load();
        if (s_XInputEnable)
            s_XInputEnable(enable);
    }

    DWORD WINAPI XInputGetAudioDeviceIds(DWORD dwUserIndex, LPWSTR pRenderDeviceId, UINT* pRenderCount, LPWSTR pCaptureDeviceId, UINT* pCaptureCount)
    {
        if (!s_XInputGetAudioDeviceIds)
            load();
        if (!s_XInputGetAudioDeviceIds)
            return ERROR_DEVICE_NOT_CONNECTED;
        return s_XInputGetAudioDeviceIds(dwUserIndex, pRenderDeviceId, pRenderCount, pCaptureDeviceId, pCaptureCount);
    }

    DWORD WINAPI XInputGetBatteryInformation(DWORD dwUserIndex, BYTE devType, XINPUT_BATTERY_INFORMATION* pBatteryInformation)
    {
        if (!s_XInputGetBatteryInformation)
            load();
        if (!s_XInputGetBatteryInformation)
            return ERROR_DEVICE_NOT_CONNECTED;
        return s_XInputGetBatteryInformation(dwUserIndex, devType, pBatteryInformation);
    }

    DWORD WINAPI XInputGetCapabilities(DWORD dwUserIndex, DWORD dwFlags, XINPUT_CAPABILITIES* pCapabilities)
    {
        if (!s_XInputGetCapabilities)
            load();
        if (!s_XInputGetCapabilities)
            return ERROR_DEVICE_NOT_CONNECTED;
        return s_XInputGetCapabilities(dwUserIndex, dwFlags, pCapabilities);
    }

    DWORD WINAPI XInputGetKeystroke(DWORD dwUserIndex, DWORD dwReserved, XINPUT_KEYSTROKE* pKeystroke)
    {
        if (!s_XInputGetKeystroke)
            load();
        if (!s_XInputGetKeystroke)
            return ERROR_DEVICE_NOT_CONNECTED;
        return s_XInputGetKeystroke(dwUserIndex, dwReserved, pKeystroke);
    }

    DWORD WINAPI XInputGetState(DWORD dwUserIndex, XINPUT_STATE* pState)
    {
        if (!s_XInputGetState)
            load();
        if (!s_XInputGetState)
            return ERROR_DEVICE_NOT_CONNECTED;
        return s_XInputGetState(dwUserIndex, pState);
    }

    DWORD WINAPI XInputSetState(DWORD dwUserIndex, void* pVibration)
    {
        if (!s_XInputSetState)
            load();
        if (!s_XInputSetState)
            return ERROR_DEVICE_NOT_CONNECTED;
        return s_XInputSetState(dwUserIndex, pVibration);
    }

#ifdef __cplusplus
}
#endif
