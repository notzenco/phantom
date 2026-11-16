/* Code that runs before the program's entry point: a TLS callback on Windows
 * and a preinit routine on Linux. Protection must leave its strings readable
 * while still encrypting the ones only main uses. */
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

static void NTAPI early(PVOID module, DWORD reason, PVOID reserved) {
    static const char msg[] = "early:before-entry\n";
    DWORD written;
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, sizeof msg - 1, &written, NULL);
    }
}

__attribute__((section(".CRT$XLB"), used)) PIMAGE_TLS_CALLBACK early_callback = early;
#else
#include <unistd.h>

static void early(int argc, char **argv, char **envp) {
    static const char msg[] = "early:before-entry\n";
    (void)argc;
    (void)argv;
    (void)envp;
    write(1, msg, sizeof msg - 1);
}

__attribute__((section(".preinit_array"), used)) static void (*early_entry)(int, char **, char **) = early;
#endif

int main(void) {
    printf("late:%s\n", "after-entry");
    return 0;
}
