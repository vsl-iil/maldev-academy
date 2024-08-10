#include <stdio.h>
#include <windows.h>
#include "../unduck.h"

int main(void) {
	unduck();

 	// метод 1
	PVOID pAddress1 = malloc(100);
	printf("[malloc] Память выделена по адресу 0x%p\n", pAddress1);

	free(pAddress1);

	// метод 2
	PVOID pAddress2 = HeapAlloc(GetProcessHeap(), 0, 100);
	printf("[HeapAlloc] Память выделена по адресу 0x%p\n", pAddress2);

	RtlFillMemory(pAddress2, 100, 0xab);

	printf("Filled mem");

	HeapFree(GetProcessHeap(), 0, pAddress2);


	// метод 3
	PVOID pAddress3 = LocalAlloc(LPTR, 100);
	printf("[LocalAlloc] Память выделена по адресу 0x%p\n", pAddress3);

	LocalFree(pAddress3);

	// метод 4 - VirtualAlloc
	PVOID pAddress4 = VirtualAlloc(
		NULL, 
		100, 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_READWRITE
	);

	printf("[VirtualAlloc] Память выделена по адресу 0x%p\n", pAddress4);

	VirtualFree(pAddress4, 0, MEM_RELEASE);
}