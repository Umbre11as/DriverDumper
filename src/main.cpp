// ReSharper disable CppLocalVariableMayBeConst
#include "utils.h"
#include <CaveHook.h>
#include <ntimage.h>

#define Log(Format, ...) DbgPrintEx(0, 0, Format, __VA_ARGS__)

bool ReadMdl(IN PVOID Address, IN PVOID Buffer, IN SIZE_T Size) {
    PMDL mdl = IoAllocateMdl(Address, Size, false, false, nullptr);
    if (!mdl)
        return false;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, false, NormalPagePriority);
    if (!mappedAddress)
        return false;

    if (!NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_READWRITE)))
        return false;

    memcpy(Buffer, Address, Size);

    MmUnmapLockedPages(mappedAddress, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return true;
}

PVOID original;

NTSTATUS NTAPI PnpCallDriverEntryDetour(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
    if (RegistryPath && RegistryPath->Buffer)
        Log("Registry path: %ws\n", RegistryPath->Buffer);

    PVOID base = nullptr;
    SIZE_T size = 0;
    GetSystemModule("EasyAntiCheat_EOS.sys", &base, &size); // Лень писать передачу из usermode
    if (!base) {
        Log("Not found\n");
        return reinterpret_cast<decltype(&PnpCallDriverEntryDetour)>(original)(DriverObject, RegistryPath);
    }

    auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(base);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dosHeader + dosHeader->e_lfanew);
    SIZE_T sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    NTSTATUS status = reinterpret_cast<decltype(&PnpCallDriverEntryDetour)>(original)(DriverObject, RegistryPath);

    // ReSharper disable CppDeprecatedEntity
    auto buffer = static_cast<UCHAR*>(ExAllocatePool(NonPagedPool, sizeOfImage));
    // ReSharper restore CppDeprecatedEntity
    ReadMdl(base, buffer, sizeOfImage);

    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, L"\\DosDevices\\C:\\dumped.sys");

    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    InitializeObjectAttributes(&objectAttributes, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    ZwCreateFile(&fileHandle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &objectAttributes, &ioStatusBlock, nullptr, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    ZwWriteFile(fileHandle, nullptr, nullptr, nullptr, &ioStatusBlock, buffer, sizeOfImage, nullptr, nullptr);
    ZwClose(fileHandle);

    return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT, IN PUNICODE_STRING) {
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
    if (!CaveHook(reinterpret_cast<ULONGLONG>(pnpCallDriverEntryAddress), PnpCallDriverEntryDetour, &original)) {
        Log("Cannot hook PnpCallDriverEntry: 0x%lX\n", CaveLastError());
        return STATUS_NOT_FOUND;
    }

    return status;
}
