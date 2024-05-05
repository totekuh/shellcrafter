#include <windows.h>
#include <stdio.h>

// Function prototypes
void run_shellcode_on_windows(BYTE *shellcode, size_t shellcode_size, int interactive);

int main() {
    // Shellcode with NOPs (0x90) for testing
    BYTE shellcode[] = {0x90, 0x90, 0x90, 0x90, 0x90}; // NOP NOP NOP NOP NOP
    size_t shellcode_size = sizeof(shellcode);
    run_shellcode_on_windows(shellcode, shellcode_size, 1);
    return 0;
}

void run_shellcode_on_windows(BYTE *shellcode, size_t shellcode_size, int interactive) {
    LPVOID ptr = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ptr) {
        printf("Failed to allocate memory.\n");
        return;
    }

    printf("[*] Shellcode located at address 0x%p\n", ptr);
    memcpy(ptr, shellcode, shellcode_size);

    if (interactive) {
        printf("[!] Press Enter to execute shellcode\n");
        getchar();
    }

    printf("[*] Executing shellcode...\n");
    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ptr, NULL, 0, &threadID);
    if (!hThread) {
        printf("Failed to create thread.\n");
        return;
    }

    WaitForSingleObject(hThread, INFINITE);
}

