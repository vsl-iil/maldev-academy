#include <windows.h>
#include <stdio.h>
#include <string.h>

//extern __declspec(dllexport)
BOOL WINAPI DllMain(
    HINSTANCE   hModule,
    DWORD       fdwReason,
    LPVOID      lpvReserved )
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            printf("[DLL] attached!\n");
            break;
        
        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            printf("[DLL] detached!\n");
            if (lpvReserved != NULL) {
                break;
            }
            break;
    }

    return TRUE;
}

extern __declspec(dllexport)
int hello_world(LPCSTR name) {
    printf("[DLL] Привет, %s!\n", name);
    
    return strlen(name);
}