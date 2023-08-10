#include "pch.h"

#include "Crypto.h"
#include "base64.h"
#include "AntiVM.h"
#include "AntiDebugger.h"
#include <iostream>
#include <process.h>

#pragma comment (linker, "/INCLUDE:_tls_used")  
#pragma comment (linker, "/INCLUDE:tls_callback_func") 

unsigned int __stdcall AntiDebugger(PVOID pM) {
    DetectResult VMwareRes = IsVMwarePresentProcess();
    switch (VMwareRes)
    {
    case DetectResult::HasVM: {
        printf("Detected VMware;)\n");
        break;
    }
    case DetectResult::Unknown: {
        printf("Unknown error!\n");
        break;
    }
    case DetectResult::NoVM:
        break;
    default:
        break;
    }

    while (true) {
        DetectResult DebuggerRes = IsDebuggerPresentVEH2D();
        switch (DebuggerRes) {
        case DetectResult::HasDebugger: {
            MessageBoxA(NULL, "Hello DebuggerHacker;)", "Hello", NULL);
            ExitProcess(0);
            break;
        }
        case DetectResult::Unknown: {
            printf("Unknown error!\n");
            break;
        }
        case DetectResult::NoDebugger:
            break;
        default:
            break;
        }
    }
    return 0;
}

char* Name, *RegisterCode;

void check(char* Cipher) {
    auto base64_cipher = base64::to_base64(std::string(Cipher));

    //std::cout << base64_cipher << std::endl;

    if (!strcmp(base64_cipher.c_str(), RegisterCode)) {
        std::cout << "Congratulations! :)\n";
    }
    else {
        std::cout << "Not this flag.\n";
    }
}

void CatchMe() {
    Name = new char[100];
    RegisterCode = new char[100];

    printf("Hello!\n");
    printf("Please input your name: ");

    std::cin >> Name;

    if (strlen(Name) <= 8 || strlen(Name) >= 50) {
        printf("Your name is too short or too long -_-!\n");
        ExitProcess(0);
    }

    printf("Please input your Base64 register code: ");

    std::cin >> RegisterCode;

    unsigned char * Key = new BYTE[20];

    unsigned char * BytePtr = reinterpret_cast<unsigned char *>(&CatchMe);
    for (size_t i = 0; i < 8; i++) {
        *(Key + i) = static_cast<BYTE>(BytePtr[i]);
    }

    for (size_t i = 8; i < 16; i++) {
        *(Key + i) = static_cast<BYTE>(BytePtr[i + 8]);
    }

    Crypto* crypto = new Crypto(Key, 16);

    unsigned char* Cipher = crypto->Encrypt(reinterpret_cast<unsigned char*>(Name), strlen(Name));

    check((char*)Cipher);

    system("pause");

    delete crypto;
    delete[] Key;
    delete[] Name;
    delete[] RegisterCode;
}

void NTAPI tls_callback(PVOID Dllhandle, DWORD Reason, PVOID Reserved) {
    if (IsDebuggerPresentPEB() == DetectResult::HasDebugger ||
        IsDebuggerPresentNtGlobalFlag() == DetectResult::HasDebugger ||
        IsDebuggerPresentHeapFlags() == DetectResult::HasDebugger ||
        IsDebuggerPresentCheckRemoteDebuggerPresent() == DetectResult::HasDebugger ||
        IsDebuggerPresentProcessDebugPort() == DetectResult::HasDebugger ||
        IsDebuggerPresentProcessBasicInformation() == DetectResult::HasDebugger ||
        IsDebuggerPresentProcessDebugObjectHandle() == DetectResult::HasDebugger ||
        IsDebuggerPresentProcessDebugFlags() == DetectResult::HasDebugger ||
        IsDebuggerPresentVEH3() == DetectResult::HasDebugger ||
        IsDebuggerPresentVEH2D() == DetectResult::HasDebugger ||
        IsDebuggerPresentHardwareDebugRegisters() == DetectResult::HasDebugger ||
        IsDebuggerPresentSoftwareBreakpoints(reinterpret_cast<unsigned char*>(&AntiDebugger)) == DetectResult::HasDebugger ||
        IsDebuggerPresentSoftwareBreakpoints(reinterpret_cast<unsigned char*>(&CatchMe)) == DetectResult::HasDebugger) {
        MessageBoxA(NULL, "Hello DebuggerHacker;)", "Hello", NULL);
        ExitProcess(0);
    }

    if (IsVMwarePresentDirectory() == DetectResult::HasVM ||
        IsVMwarePresentProcess() == DetectResult::HasVM ||
        IsVMwarePresentCPUID() == DetectResult::HasVM) {
        MessageBoxA(NULL, "Hello VMwareHacker;)", "Hello", NULL);
        ExitProcess(0);
    }
}

#ifdef _WIN64
#pragma const_seg(".CRT$XLF")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLF")
EXTERN_C
#endif //_WIN64
PIMAGE_TLS_CALLBACK tls_callback_func[] = { tls_callback,0 };
#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif //_WIN64

int main() {
    HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, AntiDebugger, NULL, 0, NULL);

    if (hThread == NULL) {
        printf("_beginthreadex failed!\n");
        ExitProcess(0);
    }

    CatchMe();

	return 0;
}