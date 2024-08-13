#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(void) {
    char identifier[32];

    scanf_s("%31s", &identifier, (unsigned)_countof(identifier));
    HANDLE h_notepad = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, atoi(identifier));

    // а здесь программа просто крашится, не смотря ни на что. Правильно, 
    // зачем возвращать код ошибки черещ GetLastError, если можно просто убить 
    // программу? 

    if (h_notepad == NULL) {
        printf("Ошибка: %lu\n", GetLastError());
        return EXIT_FAILURE;
    } else {
        printf("Дескриптор notepad.exe: %lu\n", *(unsigned long*)h_notepad);
    }
}