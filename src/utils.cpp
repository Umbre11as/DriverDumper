// ReSharper disable CppDeprecatedEntity
// Because ExAllocatePool
// ReSharper disable CppParameterMayBeConst
#include "utils.h"

NTSTATUS GetSystemModule(IN PCSTR Path, OUT PVOID* Base, OUT SIZE_T* Size) {
    NTSTATUS status = STATUS_NOT_FOUND;

    ULONG size = 0;
    if ((status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, size, &size)) != STATUS_INFO_LENGTH_MISMATCH)
        return status;

    if (size <= 0)
        return STATUS_INVALID_BUFFER_SIZE;

    const auto processModules = static_cast<PRTL_PROCESS_MODULES>(ExAllocatePool(NonPagedPool, size));
    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, processModules, size, &size)))
        return status;

    if (!processModules)
        return STATUS_BUFFER_ALL_ZEROS;

    for (ULONG i = 0; i < processModules->NumberOfModules; i++) {
        const RTL_PROCESS_MODULE_INFORMATION moduleInformation = processModules->Modules[i];
        if (strcmp(moduleInformation.FullPathName + moduleInformation.OffsetToFileName, Path) == 0) {
            *Base = moduleInformation.ImageBase;
            *Size = moduleInformation.ImageSize;

            status = STATUS_SUCCESS;
            break;
        }
    }

    ExFreePool(processModules);
    return status;
}

bool DataCompare(IN UCHAR* Data, IN UCHAR* Bytes, IN PCSTR Mask) {
    for (; *Mask; ++Mask, ++Data, ++Bytes)
        if (*Mask == 'x' && *Data != *Bytes)
            return false;

    return *Mask == 0;
}

PVOID FindSignature(IN PVOID Base, IN SIZE_T Size, IN UCHAR* Bytes, IN PCSTR Mask) {
    for (ULONGLONG i = 0; i < Size; i++)
        if (DataCompare(reinterpret_cast<UCHAR*>(reinterpret_cast<ULONGLONG>(Base) + i), Bytes, Mask))
            return reinterpret_cast<PVOID>(reinterpret_cast<ULONGLONG>(Base) + i);

    return nullptr;
}
