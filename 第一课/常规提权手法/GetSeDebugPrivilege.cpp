#include <iostream>
#include <windows.h>
#include <string>

BOOL EnableDebugPrivilege() {
    HANDLE TokenHandle = NULL;
    TOKEN_PRIVILEGES TokenPrivilege;

    LUID uID;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID)) {
            TokenPrivilege.PrivilegeCount = 1;
            TokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            TokenPrivilege.Privileges[0].Luid = uID;
            if (AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                CloseHandle(TokenHandle);
                TokenHandle = INVALID_HANDLE_VALUE;
                return TRUE;
            }
            else
                goto Fail;

        }
        else
            goto Fail;
    }
    else
        goto Fail;

    Fail:
        CloseHandle(TokenHandle);
        TokenHandle = INVALID_HANDLE_VALUE;
        return FALSE;
}