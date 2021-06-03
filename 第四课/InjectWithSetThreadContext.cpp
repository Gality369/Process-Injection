// InjectWithSetThreadContext.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
using namespace std;

//使能seDebug权限
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


//列出指定进程的所有线程
BOOL GetProcessThreadList(DWORD th32ProcessID) {
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 th32;
    printf("Trying to list all threads in Pid: %ld\n", th32ProcessID);
    //对指定进程拍摄快照
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, th32ProcessID);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return(FALSE);
    //使用前先填写结构的大小
    th32.dwSize = sizeof(THREADENTRY32);
    //检索有关第一个线程的信息
    if (!Thread32First(hThreadSnap, &th32))
    {
        CloseHandle(hThreadSnap);
        return FALSE;
    }
    //循环枚举线程列表并显示有关线程的信息
    do
    {
        if (th32.th32OwnerProcessID == th32ProcessID)
        {
            printf("\tThreadID: %ld \t", th32.th32ThreadID); //显示找到的线程的ID
            printf("\tbase priority: %ld\n", th32.tpBasePri); //显示线程优先级
        }
    } while (Thread32Next(hThreadSnap, &th32));
    //清除快照对象
    CloseHandle(hThreadSnap);
    return TRUE;
}


BOOL DoInjection(HANDLE hProcess, HANDLE hThread, CHAR* wzDllFullPath) {
//待注入的代码模板
#ifdef _WIN64
    BYTE code[] = {
    0x48, 0x83, 0xEC, 0x28,             //sub         rsp,28h
    0x48, 0x89, 0x44, 0x24, 0x18,       //mov         qword ptr [rsp+18h],rax           
    0x48, 0x89, 0x4C, 0x24, 0x10,       //mov         qword ptr [rsp+10h],rcx 
    0x48, 0xB9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,  //mov         rcx,1111111111111111h 
    0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,  //mov         rax,2222222222222222h
    0xFF, 0xD0,                         //call        rax
    0x48, 0x8B, 0x4C, 0x24, 0x10,       //mov         rcx,qword ptr [rsp+10h]
    0x48, 0x8B, 0x44, 0x24, 0x18,       //mov         rax,qword ptr [rsp+18h]
    0x48, 0x83, 0xC4, 0x28,             //add         rsp,28h
    0x48, 0x83, 0xEC, 0x08,             //sub         rsp,8
    0xC7, 0x04, 0x24, 0x33, 0x33, 0x33, 0x33,  //mov         dword ptr [rsp],33333333h
    0xC7, 0x44, 0x24, 0x04, 0x33, 0x33, 0x33, 0x33, //mov dword ptr [rsp + 4], 33333333h
    0xC3                                //ret
};
#else
    BYTE code[] = {
    0x60,
    0x68, 0x11, 0x11, 0x11, 0x11,
    0xb8, 0x22, 0x22, 0x22, 0x22,
    0xff, 0xd0,
    0x61,
    0x68, 0x33, 0x33, 0x33, 0x33,
    0xc3
    };
#endif // _WIN64


    //申请内存
    WCHAR* buffer = NULL;
    SIZE_T page_size = 4096;
    buffer = (WCHAR*)VirtualAllocEx(hProcess, nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) {
        VirtualFreeEx(hProcess, buffer, page_size, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("Buffer in remote Process: %p\n", buffer);

    //挂起目前线程
    if (SuspendThread(hThread) == -1) {
        VirtualFreeEx(hProcess, buffer, page_size, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }
    //获取线程上下文
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        VirtualFreeEx(hProcess, buffer, page_size, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    //获取LoadLibrary地址
    auto loadLibraryAddress = ::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
#ifdef _WIN64
    //根据地址，修补我们的代码
    //修补dll的地址，我们等会儿会把dll地址复制到buffer + 0x60 的位置
    * reinterpret_cast<PVOID*>(code + 0x10) = static_cast<void*>(buffer + 0x60);
    //修补LoadLibrary的地址
    *reinterpret_cast<PVOID*>(code + 0x1a) = static_cast<void*>(loadLibraryAddress);
    //修补返回地址，为当前停止的地址的低32位
    *reinterpret_cast<unsigned int*>(code + 0x39) = context.Rip & 0xFFFFFFFF;
    //修补返回地址，为当前停止的地址的高32位
    *reinterpret_cast<unsigned int*>(code + 0x41) = context.Rip >> 32 ;
#else
    //根据地址，修补我们的代码
    //修补dll的地址，我们等会儿会把dll地址复制到buffer + 0x60 的位置
    *reinterpret_cast<PVOID*>(code + 2) = static_cast<void*>(buffer + 0x60);
    //修补LoadLibrary的地址
    *reinterpret_cast<PVOID*>(code + 7) = static_cast<void*>(loadLibraryAddress);
    //修补返回地址，为当前停止的地址（eip指向即将执行代码的地址）
    *reinterpret_cast<unsigned*>(code + 0xf) = context.Eip;
#endif // _WIN64

    //把函数复制到内存中
    if (!WriteProcessMemory(hProcess, buffer, code, sizeof(code), nullptr)) {
        VirtualFreeEx(hProcess, buffer, page_size, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }
    //把Dll的路径复制到内存中
    if (!WriteProcessMemory(hProcess, buffer + 0x60, wzDllFullPath, (strlen(wzDllFullPath)+1)*sizeof(wzDllFullPath), nullptr)) {
        VirtualFreeEx(hProcess, buffer, page_size, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    //将新的指令指针指向添加的代码并恢复线程执行
#ifdef _WIN64
    context.Rip = reinterpret_cast<unsigned long long>(buffer);
#else
    context.Eip = reinterpret_cast<DWORD>(buffer);
#endif // _win64

    if (!SetThreadContext(hThread, &context)) {
        VirtualFreeEx(hProcess, buffer, page_size, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }
    ResumeThread(hThread);

    return TRUE;
}


int _tmain(int argc, _TCHAR* argv[])
{
    if (EnableDebugPrivilege() == FALSE) {
        return 0;
    }
    ULONG32 ulProcessID = 0;
    ULONG32 ulThreadID = 0;
    printf("Input the Process ID:");
    cin >> ulProcessID;
    CHAR wzDllFullPath[MAX_PATH] = { 0 };

#ifndef _WIN64
    strcpy_s(wzDllFullPath, "D:\\project\\TestDll\\Release\\TestDll.dll");
#else // _WIN64
    strcpy_s(wzDllFullPath, "D:\\project\\TestDll\\x64\\Release\\TestDll.dll");
#endif

    if (!GetProcessThreadList(ulProcessID)) {
        printf("Can not list the threads!");
        exit(0);
    }
    printf("Input the Thread ID:");
    cin >> ulThreadID;
    //打开句柄资源
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, ulProcessID);
    if (hProcess == NULL) {
        printf("failed to open Process");
        return FALSE;
    }
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, ulThreadID);
    if (hThread == NULL) {
        printf("failed to open Thread");
        return FALSE;
    }
    //注入
    if (!DoInjection(hProcess, hThread, wzDllFullPath)) {
        printf("Failed to inject DLL");
        return FALSE;
    }
    return 0;
}
