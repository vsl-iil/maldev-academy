#include <stdio.h>
#include <windows.h>
#include "../unduck.h"

typedef int (WINAPI* fnHelloWorld)(LPCSTR name);

int main(void) {
    unduck();
    printf("[main] Подключаем DLL...\n");

    // загружаем DLL
    HMODULE hModule = LoadLibraryA("mydll.dll");

    // получаем адрес функции
    fnHelloWorld hello_world = (fnHelloWorld)GetProcAddress(hModule, "hello_world");

    if (hello_world != NULL) {
        // вызываем функцию по указателю
        hello_world("visilii");
    }

    scanf("Сейчас можешь проверить в Process Hacker загруженный DLL...");

    printf("[main] Завершаем работу программы...\n");
}