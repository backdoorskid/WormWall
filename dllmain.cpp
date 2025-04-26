#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include "minhook.h"
#include <winnt.h>
#include <winternl.h>

typedef BOOL (WINAPI* SHELLEXECUTEEXA)(SHELLEXECUTEINFOA*);
typedef BOOL (WINAPI* SHELLEXECUTEEXW)(SHELLEXECUTEINFOW*);
SHELLEXECUTEEXA oShellExecuteExA = NULL;
SHELLEXECUTEEXW oShellExecuteExW = NULL;

BOOL WINAPI DetourShellExecuteExA(
    SHELLEXECUTEINFOA* pExecInfo
) {
    std::string parameters(pExecInfo->lpParameters);
    std::string originalParameters(parameters);
    if (parameters.contains("cmdkey /generic")) {
        std::cout << "[+] Prevented a possible remote code execution attempt\n";
        std::cout << "[+] Command Line: cmd.exe ";
        std::cout << parameters << "\n";

        CHAR newParameters[8] = "/c echo";
        newParameters[7] = '\0';
        pExecInfo->lpParameters = newParameters;

        parameters = std::string(pExecInfo->lpParameters);
        std::cout << "[+] Updated Command Line:  cmd.exe ";
        std::cout << parameters << "\n";
    }

    oShellExecuteExA(pExecInfo);
    pExecInfo->lpParameters = originalParameters.c_str();
}

BOOL WINAPI DetourShellExecuteExW(
    SHELLEXECUTEINFOW* pExecInfo
) {
    std::wstring parameters(pExecInfo->lpParameters);
    std::wstring originalParameters(parameters);
    if (parameters.contains(L"cmdkey /generic")) {
        std::cout << "[+] Prevented a possible remote code execution attempt\n";
        std::cout << "[+] Original Command Line: cmd.exe ";
        std::wcout << parameters << "\n";
        
        WCHAR newParameters[8] = L"/c echo";
        newParameters[7] = L'\0';
        pExecInfo->lpParameters = newParameters;

        parameters = std::wstring(pExecInfo->lpParameters);
        std::cout << "[+] Updated Command Line:  cmd.exe ";
        std::wcout << parameters << "\n";
    }

    oShellExecuteExW(pExecInfo);
    pExecInfo->lpParameters = originalParameters.c_str();
}

BOOL InstallMicropatch() {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);

    HANDLE hStdOut = CreateFileW(L"CONOUT$", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    DWORD dwMode = 0;
    if (GetConsoleMode(hStdOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hStdOut, dwMode);
    }

    std::cout << "\x1b[1;38;5;14m";
    std::cout << "[+] WormWall - Do not close this window" << std::endl;
    std::cout << "[+] This DLL must be injected everytime you open up XWORM and before you start listening for connections" << std::endl;
    std::cout << "\x1b[1;33m";

    FARPROC aShellExecuteExA = GetProcAddress(LoadLibraryA("shell32.dll"), "ShellExecuteExA");
    FARPROC aShellExecuteExW = GetProcAddress(LoadLibraryA("shell32.dll"), "ShellExecuteExW");
    if (aShellExecuteExA == 0 || aShellExecuteExW == 0) {
        std::cout << "\x1b[1;31m";
        std::cout << "[-] Failed to get addresses for ShellExecute\n";
        goto ERROR_CONDITION;
    }
    std::cout << "[+] Obtained ShellExecuteExA address: " << std::hex << aShellExecuteExA << "\n";
    std::cout << "[+] Obtained ShellExecuteExW address: " << std::hex << aShellExecuteExW << "\n";

    if (MH_Initialize() != MH_OK) {
        std::cout << "\x1b[1;31m";
        std::cout << "[-] Failed to initialize minhook\n";
        goto ERROR_CONDITION;
    }
    std::cout << "[+] Initialized minhook\n";

    if (MH_CreateHook(aShellExecuteExA, &DetourShellExecuteExA, reinterpret_cast<LPVOID*>(&oShellExecuteExA)) != MH_OK) {
        std::cout << "\x1b[1;31m";
        std::cout << "[-] Failed to create hook for ShellExecuteExA\n";
        goto ERROR_CONDITION;
    }
    std::cout << "[+] Created hook for ShellExecuteExA\n";
    if (MH_EnableHook(aShellExecuteExA) != MH_OK) {
        std::cout << "\x1b[1;31m";
        std::cout << "[-] Failed to enable hook for ShellExecuteExA\n";
        goto ERROR_CONDITION;
    }
    std::cout << "[+] Enabled hook for ShellExecuteExA\n";
    if (MH_CreateHook(aShellExecuteExW, &DetourShellExecuteExW, reinterpret_cast<LPVOID*>(&oShellExecuteExW)) != MH_OK) {
        std::cout << "\x1b[1;31m";
        std::cout << "[-] Failed to create hook for ShellExecuteExW\n";
        goto ERROR_CONDITION;
    }
    std::cout << "[+] Created hook for ShellExecuteExW\n";
    if (MH_EnableHook(aShellExecuteExW) != MH_OK) {
        std::cout << "\x1b[1;31m";
        std::cout << "[-] Failed to enable hook for ShellExecuteExW\n";
        goto ERROR_CONDITION;
    }
    std::cout << "[+] Enabled hook for ShellExecuteExW\n\n";

    
    std::cout << "\x1b[1;38;5;10m";
    std::cout << "[+] The remote code execution exploit is patched in your current session\n\n";
    std::cout << "\x1b[1;38;5;14m";

    SetConsoleTitleA("XWorm | WormWall is loaded");

    return TRUE;
ERROR_CONDITION:
    std::cout << "[-] An error occured while attempting to patch the remote code execution exploit in your current session.\n";
    std::cout << "[-] Please restart your XWORM and then try again.\n";
    return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call != DLL_PROCESS_ATTACH)
        return TRUE;

    return InstallMicropatch();
}

