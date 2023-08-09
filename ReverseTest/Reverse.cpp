#include "pch.h"

#include "Crypto.h"
#include "base64.h"
#include "AntiDebugger.h"
#include "AntiVM.h"
#include <iostream>
#include <process.h>

void check(char* Cipher) {
    auto base64_cipher = base64::to_base64(std::string(Cipher));

    if (!strcmp(base64_cipher.c_str(), "GHNyJfTNvutyIJc1HQ==")) {
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
        DetectResult Res = IsDebuggerPresentVEH2D();
        switch (Res) {
        case DetectResult::HasDebugger: {
            MessageBoxA(NULL, "Hello Hacker;)", "Hello", NULL);
            ExitProcess(0);
            break;
        }
        case DetectResult::HasVM:
            break;
        case DetectResult::Unknown: {
            printf("Unknown error!\n");
            break;
        }
        case DetectResult::NoDebugger:
        case DetectResult::NoVM:
            break;
        default:
            break;
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