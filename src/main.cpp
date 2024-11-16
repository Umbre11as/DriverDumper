// ReSharper disable CppLocalVariableMayBeConst
#include "utils.h"
#include <CaveHook.h>

#define Log(Format, ...) DbgPrintEx(0, 0, Format, __VA_ARGS__)

typedef void(*PnpCallDriverEntryFn)();

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
    NTSTATUS status = STATUS_SUCCESS;

    PVOID base = nullptr;
    SIZE_T size = 0;
    if (!NT_SUCCESS(status = GetSystemModule("ntoskrnl.exe", &base, &size))) {
        Log("Error while finding ntoskrnl.exe: 0x%lX\n", status);
        return status;
    }

    Log("ntoskrnl.exe: %p\n", base);
    PVOID pnpCallDriverEntryAddress = FindSignature(
        base, size,
        reinterpret_cast<UCHAR*>("\x4C\x8B\xDC\x49\x89\x5B\x00\x49\x89\x73\x00\x57\x48\x83\xEC\x00\x49\x83\x63\x00\x00\x48\x8B\xDA\x49\x89\x4B"),
        "xxxxxx?xxx?xxxx?xxx??xxxxxx"
    );
    if (!pnpCallDriverEntryAddress) {
        Log("Cannot find PnpCallDriverEntry\n");
        return STATUS_NOT_FOUND;
    }

    Log("PnpCallDriverEntry: %p\n", pnpCallDriverEntryAddress);

    return status;
}
