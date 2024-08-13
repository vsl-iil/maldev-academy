#include <Windows.h>
#include <heapapi.h>
#include <stdio.h>
#include <string.h>
#include "resource.h"

#define handle_error(a, name) if (a == NULL) { \
                                printf("[!] %s failed with error: %lu\n", \
                                    name, \
                                    GetLastError()); \
                                return EXIT_FAILURE; } 

int main(void) {
    HRSRC   hRsrc           = NULL;
    HGLOBAL hGlobal         = NULL;
    PVOID   pPayloadAddress = NULL;
    SIZE_T  sPayloadSize    = 0;

    // Получаем местоположение данных, хранимых в .rsrc, по id
    hRsrc = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    handle_error(hRsrc, "FindResource");

    // Получаем дескриптор для LockResource
    hGlobal = LoadResource(NULL, hRsrc);
    handle_error(hGlobal, "LoadResource");

    // Получаем адрес нашей полезной нагрузки
    pPayloadAddress = LockResource(hGlobal);
    handle_error(pPayloadAddress, "LockResource");

    // Получаем размер полезной нагрузки
    sPayloadSize = SizeofResource(NULL, hRsrc);
    handle_error((void*)sPayloadSize, "SizeofResource");

    printf("[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);
	printf("[i] sPayloadSize var : %llu \n", sPayloadSize);
	
    // Выделяем память
    PVOID pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
    handle_error(pTmpBuffer, "HeapAlloc");

    memcpy_s(pTmpBuffer, sPayloadSize, pPayloadAddress, sPayloadSize);

    printf("[i] pTmpBuffer: 0x%p\n", pTmpBuffer);
}