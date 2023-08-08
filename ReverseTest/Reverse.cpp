#include "pch.h"

#include "Reverse.h"
#include "base64.h"
#include "AntiDebugger.h"
#include "AntiVM.h"
#include <iostream>
#include <process.h>

void check(char* Cipher) {
    auto base64_cipher = base64::to_base64(Cipher);
    auto your_flag = base64::to_base64(base64_cipher);

    if (!strcmp(your_flag.c_str(), "R0hOeUpmVE52dXR5SUpjMUhRPT0=")) {
        std::cout << "Done.\n";
    }
    else {
        std::cout << "Not this flag.\n";
    }
}

void CatchMe() {
    char Flag[20];
    printf("Input flag: ");
    std::cin >> Flag;

    Crypto* crypto = new Crypto("BronyaZaychik");

    char* cEncryptData = crypto->Encrypt(Flag, strlen(Flag));

    check(cEncryptData);

    system("pause");
}

unsigned int __stdcall AntiDebugger(PVOID pM) {
    while (true) {
        if (IsDebuggerPresentPEB() == DetectResult::HasDebugger) {
            //MessageBoxA(NULL, "AntiDebug", "AntiDebug", MB_OK);
            printf("No Debugger!\n");
            ExitProcess(0);
            return 0;
        }
    }

    return 0;
}

int main() {
    HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, AntiDebugger, NULL, 0, NULL);

    if (hThread == NULL) {
        printf("_beginthreadex failed!\n");
        ExitProcess(0);
    }

    CatchMe();

	return 0;
}