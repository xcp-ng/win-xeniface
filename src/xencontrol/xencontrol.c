#define INITGUID
#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <stdlib.h>
#include <assert.h>

#include "xencontrol.h"
#include "xencontrol_private.h"

BOOL APIENTRY
DllMain(
    IN  HMODULE Module,
    IN  DWORD ReasonForCall,
    IN  LPVOID Reserved
)
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(ReasonForCall);
    UNREFERENCED_PARAMETER(Reserved);
    return TRUE;
}

static void
_Log(
    IN  XENCONTROL_LOGGER *Logger,
    IN  XENCONTROL_LOG_LEVEL LogLevel,
    IN  XENCONTROL_LOG_LEVEL CurrentLogLevel,
    IN  PCHAR Function,
    IN  PWCHAR Format,
    ...
    )
{
    va_list Args;
    DWORD LastError;

    if (Logger == NULL)
        return;

    if (LogLevel > CurrentLogLevel)
        return;

    LastError = GetLastError();
    va_start(Args, Format);
    Logger(LogLevel, Function, Format, Args);
    va_end(Args);
    SetLastError(LastError);
}

static void
_LogMultiSz(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Caller,
    IN  XENCONTROL_LOG_LEVEL Level,
    IN  PCHAR MultiSz
    )
{
    PCHAR Ptr;
    ULONG Len;

    for (Ptr = MultiSz; *Ptr;) {
        Len = (ULONG)strlen(Ptr);
        _Log(Xc->Logger, Level, Xc->LogLevel, Caller, L"%S", Ptr);
        Ptr += ((ptrdiff_t)Len + 1);
    }
}

void
XcRegisterLogger(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XENCONTROL_LOGGER *Logger
    )
{
    Xc->Logger = Logger;
}

void
XcSetLogLevel(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XENCONTROL_LOG_LEVEL LogLevel
    )
{
    Xc->LogLevel = LogLevel;
}

DWORD
XcOpen(
    IN  XENCONTROL_LOGGER *Logger,
    OUT PXENCONTROL_CONTEXT *Xc
    )
{
    HDEVINFO DevInfo;
    SP_DEVICE_INTERFACE_DATA InterfaceData;
    SP_DEVICE_INTERFACE_DETAIL_DATA *DetailData = NULL;
    DWORD BufferSize;
    PXENCONTROL_CONTEXT Context;

    Context = malloc(sizeof(*Context));
    if (Context == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Context->Logger = Logger;
    Context->LogLevel = XLL_INFO;

    DevInfo = SetupDiGetClassDevs(&GUID_INTERFACE_XENIFACE, 0, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (DevInfo == INVALID_HANDLE_VALUE) {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"XENIFACE device class doesn't exist");
        goto fail;
    }

    InterfaceData.cbSize = sizeof(InterfaceData);
    if (!SetupDiEnumDeviceInterfaces(DevInfo, NULL, &GUID_INTERFACE_XENIFACE, 0, &InterfaceData)) {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to enumerate XENIFACE devices");
        goto fail;
    }

    SetupDiGetDeviceInterfaceDetail(DevInfo, &InterfaceData, NULL, 0, &BufferSize, NULL);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to get buffer size for device details");
        goto fail;
    }

    // Using 'BufferSize' from failed function call
#pragma warning(suppress: 6102)
    DetailData = (SP_DEVICE_INTERFACE_DETAIL_DATA *)malloc(BufferSize);
    if (!DetailData) {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    DetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

    if (!SetupDiGetDeviceInterfaceDetail(DevInfo, &InterfaceData, DetailData, BufferSize, NULL, NULL)) {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to get XENIFACE device path");
        goto fail;
    }

    Context->XenIface = CreateFile(DetailData->DevicePath,
                                   FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                   NULL);

    if (Context->XenIface == INVALID_HANDLE_VALUE) {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to open XENIFACE device, path: %s", DetailData->DevicePath);
        goto fail;
    }

    _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
         L"XenIface handle: %p", Context->XenIface);

    free(DetailData);
    *Xc = Context;
    return ERROR_SUCCESS;

fail:
    _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
         L"Error: 0x%x", GetLastError());

    free(DetailData);
    free(Context);
    *Xc = NULL;
    return GetLastError();
}

void
XcClose(
    IN  PXENCONTROL_CONTEXT Xc
    )
{
    CloseHandle(Xc->XenIface);
    free(Xc);
}

DWORD
XcEvtchnOpenUnbound(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    )
{
    XENIFACE_EVTCHN_BIND_UNBOUND_IN In;
    XENIFACE_EVTCHN_BIND_UNBOUND_OUT Out;
    DWORD Returned;
    BOOL Success;

    In.RemoteDomain = RemoteDomain;
    In.Event = Event;
    In.Mask = !!Mask;

    Log(XLL_DEBUG, L"RemoteDomain: %d, Event: %p, Mask: %d", RemoteDomain, Event, Mask);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND,
                              &In, sizeof(In),
                              &Out, sizeof(Out),
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND failed");
        goto fail;
    }

    *LocalPort = Out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %lu", *LocalPort);

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcEvtchnBindInterdomain(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG RemotePort,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    )
{
    XENIFACE_EVTCHN_BIND_INTERDOMAIN_IN In;
    XENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT Out;
    DWORD Returned;
    BOOL Success;

    In.RemoteDomain = RemoteDomain;
    In.RemotePort = RemotePort;
    In.Event = Event;
    In.Mask = !!Mask;

    Log(XLL_DEBUG, L"RemoteDomain: %d, RemotePort %lu, Event: %p, Mask: %d",
        RemoteDomain, RemotePort, Event, Mask);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN,
                              &In, sizeof(In),
                              &Out, sizeof(Out),
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN failed");
        goto fail;
    }

    *LocalPort = Out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %lu", *LocalPort);

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcEvtchnClose(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    )
{
    XENIFACE_EVTCHN_CLOSE_IN In;
    DWORD Returned;
    BOOL Success;

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %lu", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_CLOSE,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_CLOSE failed");
        goto fail;
    }

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcEvtchnNotify(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    )
{
    XENIFACE_EVTCHN_NOTIFY_IN In;
    DWORD Returned;
    BOOL Success;

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %lu", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_NOTIFY,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_NOTIFY failed");
        goto fail;
    }

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcEvtchnUnmask(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    )
{
    XENIFACE_EVTCHN_UNMASK_IN In;
    DWORD Returned;
    BOOL Success;

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %lu", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_UNMASK,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_UNMASK failed");
        goto fail;
    }

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcGnttabPermitForeignAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  XENIFACE_GNTTAB_PAGE_FLAGS Flags,
    OUT PVOID* SharedAddress,
    OUT ULONG* References
)
{
    Log(XLL_DEBUG, L"RemoteDomain: %d, NumberPages: %lu, NotifyOffset: 0x%x, NotifyPort: %lu, Flags: 0x%x",
        RemoteDomain, NumberPages, NotifyOffset, NotifyPort, Flags);

    return XcGnttabPermitForeignAccess2(Xc,
                                        RemoteDomain,
                                        NULL,
                                        NumberPages,
                                        NotifyOffset,
                                        NotifyPort,
                                        Flags,
                                        SharedAddress,
                                        References);
}

DWORD
XcGnttabPermitForeignAccess2(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  PVOID Address,
    IN  ULONG NumberPages,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  XENIFACE_GNTTAB_PAGE_FLAGS Flags,
    OUT PVOID *SharedAddress,
    OUT ULONG *References
    )
{
    XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN_V2 In;
    XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT_V2 *Out;
    DWORD Returned, Size;
    OVERLAPPED Overlapped;
    BOOL Success;
    DWORD Status;

    In.RemoteDomain = RemoteDomain;
    In.Address = Address;
    In.NumberPages = NumberPages;
    In.NotifyOffset = NotifyOffset;
    In.NotifyPort = NotifyPort;
    In.Flags = Flags;

    Size = (ULONG)FIELD_OFFSET(XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT_V2, References[NumberPages]);
    Out = malloc(Size);

    Status = ERROR_OUTOFMEMORY;
    if (!Out)
        goto fail;

    Log(XLL_DEBUG, L"RemoteDomain: %d, Address %p, NumberPages: %lu, NotifyOffset: 0x%x, NotifyPort: %lu, Flags: 0x%x",
        RemoteDomain, Address, NumberPages, NotifyOffset, NotifyPort, Flags);

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_V2,
                              &In, sizeof(In),
                              Out, Size,
                              &Returned,
                              &Overlapped);

    Status = GetLastError();
    // this IOCTL is expected to be pending on success
    if (!Success) {
        if (Status != ERROR_IO_PENDING) {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_V2 failed");
            goto fail;
        }
    } else {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_V2 not pending");
        Status = ERROR_UNIDENTIFIED_ERROR;
        goto fail;
    }

    *SharedAddress = Out->Address;
    memcpy(References, &Out->References, NumberPages * sizeof(ULONG));
    Log(XLL_DEBUG, L"Address: %p", Out->Address);
#ifdef _DEBUG
    for (ULONG i = 0; i < NumberPages; i++)
        Log(XLL_DEBUG, L"Grant ref[%lu]: %lu", i, Out->References[i]);
#endif

    free(Out);
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", Status);
    free(Out);
    return Status;
}

DWORD
XcGnttabRevokeForeignAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    )
{
    XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN_V2 In;
    DWORD Returned;
    BOOL Success;
    DWORD Status;

    Log(XLL_DEBUG, L"Address: %p", Address);
    In.Address = Address;

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_V2,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    Status = GetLastError();
    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_V2 failed");
        goto fail;
    }

    return Status;

fail:
    Log(XLL_ERROR, L"Error: %d 0x%x", Status, Status);
    return Status;
}

DWORD
XcGnttabMapForeignPages(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  PULONG References,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  XENIFACE_GNTTAB_PAGE_FLAGS Flags,
    OUT PVOID *Address
    )
{
    XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN_V2 *In;
    XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT_V2 Out;
    DWORD Returned, Size;
    OVERLAPPED Overlapped;
    BOOL Success;
    DWORD Status;

    Status = ERROR_OUTOFMEMORY;
    Size = (ULONG)FIELD_OFFSET(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN_V2, References[NumberPages]);
    In = malloc(Size);
    if (!In)
        goto fail;

    In->RemoteDomain = RemoteDomain;
    In->NumberPages = NumberPages;
    In->NotifyOffset = NotifyOffset;
    In->NotifyPort = NotifyPort;
    In->Flags = Flags;
    memcpy(&In->References, References, NumberPages * sizeof(ULONG));

    Log(XLL_DEBUG, L"RemoteDomain: %d, NumberPages: %lu, NotifyOffset: 0x%x, NotifyPort: %lu, Flags: 0x%x",
        RemoteDomain, NumberPages, NotifyOffset, NotifyPort, Flags);

#ifdef _DEBUG
    for (ULONG i = 0; i < NumberPages; i++)
        Log(XLL_DEBUG, L"Grant ref[%lu]: %lu", i, References[i]);
#endif

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_V2,
                              In, Size,
                              &Out, sizeof(Out),
                              &Returned,
                              &Overlapped);

    Status = GetLastError();
    // this IOCTL is expected to be pending on success
    if (!Success) {
        if (Status != ERROR_IO_PENDING) {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_V2 failed");
            goto fail;
        }
    } else {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_V2 not pending");
        Status = ERROR_UNIDENTIFIED_ERROR;
        goto fail;
    }

    *Address = Out.Address;

    Log(XLL_DEBUG, L"Address: %p", *Address);

    free(In);
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", Status);
    free(In);
    return Status;
}

DWORD
XcGnttabUnmapForeignPages(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    )
{
    XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN_V2 In;
    DWORD Returned;
    BOOL Success;
    DWORD Status;

    Log(XLL_DEBUG, L"Address: %p", Address);

    In.Address = Address;

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_V2,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    Status = GetLastError();
    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_V2 failed");
        goto fail;
    }

    return Status;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", Status);
    return Status;
}

DWORD
XcStoreRead(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PSTR Path,
    IN  DWORD cbValue,
    OUT CHAR *Value
    )
{
    DWORD Returned;
    BOOL Success;

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_READ,
                              Path, (DWORD)strlen(Path) + 1,
                              Value, cbValue,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_READ failed");
        goto fail;
    }

    Log(XLL_DEBUG, L"Value: '%S'", Value);

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcStoreWrite(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  PCHAR Value
    )
{
    PCHAR Buffer;
    DWORD cbBuffer;
    DWORD Returned;
    BOOL Success;

    cbBuffer = (DWORD)(strlen(Path) + 1 + strlen(Value) + 1 + 1);
    Buffer = malloc(cbBuffer);
    if (!Buffer) {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    ZeroMemory(Buffer, cbBuffer);
    memcpy(Buffer, Path, strlen(Path));
    memcpy(Buffer + strlen(Path) + 1, Value, strlen(Value));

    Log(XLL_DEBUG, L"Path: '%S', Value: '%S'", Path, Value);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_WRITE,
                              Buffer, cbBuffer,
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_WRITE failed");
        goto fail;
    }

    free(Buffer);
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    free(Buffer);
    return GetLastError();
}

DWORD
XcStoreDirectory(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    )
{
    DWORD Returned;
    BOOL Success;

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_DIRECTORY,
                              Path, (DWORD)strlen(Path) + 1,
                              Output, cbOutput,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_DIRECTORY failed");
        goto fail;
    }

    _LogMultiSz(Xc, __FUNCTION__, XLL_DEBUG, Output);

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcStoreRemove(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path
    )
{
    DWORD Returned;
    BOOL Success;

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_REMOVE,
                              Path, (DWORD)strlen(Path) + 1,
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_REMOVE failed");
        goto fail;
    }

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcStoreSetPermissions(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  ULONG Count,
    IN  PXENIFACE_STORE_PERMISSION Permissions
    )
{
    DWORD Returned, Size;
    BOOL Success;
    XENIFACE_STORE_SET_PERMISSIONS_IN *In = NULL;

    Log(XLL_DEBUG, L"Path: '%S', Count: %lu", Path, Count);
    for (ULONG i = 0; i < Count; i++)
        Log(XLL_DEBUG, L"Domain: %d, Mask: 0x%x", Permissions[i].Domain, Permissions[i].Mask);

    Size = (ULONG)FIELD_OFFSET(XENIFACE_STORE_SET_PERMISSIONS_IN, Permissions[Count]);
    In = malloc(Size);
    if (!In) {
        SetLastError(ERROR_OUTOFMEMORY);
        goto fail;
    }

    In->Path = Path;
    In->PathLength = (DWORD)strlen(In->Path) + 1;
    In->NumberPermissions = Count;
    memcpy(&In->Permissions, Permissions, Count * sizeof(XENIFACE_STORE_PERMISSION));

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_SET_PERMISSIONS,
                              In, Size,
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_SET_PERMISSIONS failed");
        goto fail;
    }

    free(In);
    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    free(In);
    return GetLastError();
}

DWORD
XcStoreAddWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  HANDLE Event,
    OUT PVOID *Handle
    )
{
    DWORD Returned;
    BOOL Success;
    XENIFACE_STORE_ADD_WATCH_IN In;
    XENIFACE_STORE_ADD_WATCH_OUT Out;

    Log(XLL_DEBUG, L"Path: '%S', Event: %p", Path, Event);

    In.Path = Path;
    In.PathLength = (DWORD)strlen(Path) + 1;
    In.Event = Event;
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_ADD_WATCH,
                              &In, sizeof(In),
                              &Out, sizeof(Out),
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_ADD_WATCH failed");
        goto fail;
    }

    *Handle = Out.Context;

    Log(XLL_DEBUG, L"Handle: %p", *Handle);

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}

DWORD
XcStoreRemoveWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Handle
    )
{
    DWORD Returned;
    BOOL Success;
    XENIFACE_STORE_REMOVE_WATCH_IN In;

    Log(XLL_DEBUG, L"Handle: %p", Handle);

    In.Context = Handle;
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_REMOVE_WATCH,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_REMOVE_WATCH failed");
        goto fail;
    }

    return ERROR_SUCCESS;

fail:
    Log(XLL_ERROR, L"Error: 0x%x", GetLastError());
    return GetLastError();
}
