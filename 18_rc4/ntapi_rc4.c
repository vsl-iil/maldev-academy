#include <Windows.h>
#include <bcrypt.h>
#include <errhandlingapi.h>
#include <libloaderapi.h>
#include <minwindef.h>
#include <stdio.h>
#include <string.h>
#include "../unduck.h"

// RC4-шифрование с использованием функции из NTAPI 
// SystemFunction032

// Определение взято из документации Wine:
// https://source.winehq.org/WineAPI/SystemFunction032.html
typedef NTSTATUS (WINAPI* fnSystemFunction032)(
    struct ustring*         data,
    const struct ustring*   key
);

// https://github.com/wine-mirror/wine/blob/master/dlls/advapi32/crypt.h#L94
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    unsigned char* Buffer;
} ustring;

BOOL encryptRC4(IN PBYTE pKey, IN OUT PBYTE pPayload, IN DWORD dwKeySize, IN DWORD sPayloadSize) {
    NTSTATUS STATUS = 0;

    ustring Data = {
        .Buffer         = pPayload,
        .Length         = sPayloadSize,
        .MaximumLength  = sPayloadSize,
    };

    ustring Key = {
        .Buffer         = pKey,
        .Length         = dwKeySize,
        .MaximumLength  = dwKeySize,
    };

    HMODULE hModule = LoadLibraryA("Advapi32.dll");
    fnSystemFunction032 NtRC4Encrypt = (fnSystemFunction032)GetProcAddress(hModule, "SystemFunction032");

    if (NtRC4Encrypt == NULL) {
        printf("[!] Не удалось импортировать функцию из Advapi32.dll! Ошибка: %lu\n", GetLastError());
        return FALSE;
    } 

    if ((STATUS = NtRC4Encrypt(&Data, &Key)) != 0) {
        printf("[!] SystemFunction032 вернула ошибку 0x%0.8lX\n", STATUS);
        return FALSE;
    }

    //printf("[+] Шифротекст: ");
    //PBYTE cipher = Data.Buffer;
    //while(*cipher) {
        //printf("%02X", (unsigned int)*cipher++);
    //}
    //printf("\n");

    return TRUE;
}

void print_hex(unsigned char* arr, size_t size) {
    for (int i = 0; i < size; i++) {
        printf("%0.2X ", arr[i]);
    }
}

int main(void) {
    unduck();
    
    unsigned char* payload   = "The quick brown fox jumps over the lazy dog.";
    unsigned char key[]       = {
        63, 72, 79, 70, 74, 69, 69
    };
    printf("[i] Выполняем функцию encryptRC4...\n");
    printf("[i] Исходный текст: %s\n", payload);
    printf("[i] Ключ: %s\n", key);

    encryptRC4(key, payload, strlen(key), strlen(payload));

    printf("[+] Шифротекст: %s\n", payload);

    print_hex(payload, strlen(payload));

    encryptRC4(key, payload, strlen(key), strlen(payload));

    printf("[+] Расшифрованное сообщение: %s\n", payload);
}