#include <windows.h>
//#include <tchar.h>
#include <stdio.h>
#include <Lmcons.h>
#include "../unduck.h"

int main(void) {
    unduck();
    char name_buf[UNLEN+1];
    DWORD buflen = UNLEN+1;

    /* 
     * ERROR_INSUFFICIENT_BUFFER
     * 122 (0x7A)
     * The data area passed to a system call is too small.
     */
    //DWORD buflen = 1;

    GetUserName((TCHAR*)name_buf, &buflen);

    if (GetUserName(name_buf, &buflen) == 0) {
        printf("Ошибка: %lu", GetLastError());
    } else {
        printf("Юзернейм: %s", name_buf);
    }
}