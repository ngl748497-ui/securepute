#include "pch.h"
#include <windows.h>
#include <iostream>
#include <string>

void LogDebug(const char* message) {
    OutputDebugStringA("[DLL Payload] ");
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

DWORD WINAPI PayloadWorkerThread(LPVOID lpParam)
{
    while (TRUE) // Thêm vòng lặp vô tận
    {
        LogDebug("Worker thread loop started.");

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if (CreateProcessA(NULL, (LPSTR)"test.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            LogDebug("Successfully created process test.exe.");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else
        {
            char errorMsg[256];
            sprintf_s(errorMsg, "Failed to create process. Error code: %d", GetLastError());
            LogDebug(errorMsg);
        }

        char systemPath[MAX_PATH];
        UINT pathLen = GetSystemDirectoryA(systemPath, MAX_PATH);

        if (pathLen > 0)
        {
            std::string filePath = std::string(systemPath) + "\\injected_log.txt";
            HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (hFile != INVALID_HANDLE_VALUE)
            {
                const char* content = "This is a test file created by the injected DLL.";
                DWORD bytesWritten;
                if (WriteFile(hFile, content, (DWORD)strlen(content), &bytesWritten, NULL))
                {
                    LogDebug("Successfully wrote to injected_log.txt in System32.");
                }
                CloseHandle(hFile);
            }
        }

        LogDebug("Worker thread sleeping for 3 seconds.");
        Sleep(3000); 
    }

    return 0; 
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    { 
        DisableThreadLibraryCalls(hinstDLL);

        HANDLE hThread = CreateThread(
            NULL,
            0,
            PayloadWorkerThread,
            NULL,
            0,
            NULL
        );

        if (hThread) {
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}