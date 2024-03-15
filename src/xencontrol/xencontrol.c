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
    DWORD Status = ERROR_OUTOFMEMORY;

    Context = malloc(sizeof(*Context));
    if (Context == NULL)
        goto end;

    Context->Logger = Logger;
    Context->LogLevel = XLL_INFO;

    DevInfo = SetupDiGetClassDevs(&GUID_INTERFACE_XENIFACE, 0, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (DevInfo == INVALID_HANDLE_VALUE) {
        Status = GetLastError();
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"XENIFACE device class doesn't exist: 0x%x", Status);
        goto end;
    }

    InterfaceData.cbSize = sizeof(InterfaceData);
    if (!SetupDiEnumDeviceInterfaces(DevInfo, NULL, &GUID_INTERFACE_XENIFACE, 0, &InterfaceData)) {
        Status = GetLastError();
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to enumerate XENIFACE devices: 0x%x", Status);
        goto end;
    }

    SetupDiGetDeviceInterfaceDetail(DevInfo, &InterfaceData, NULL, 0, &BufferSize, NULL);
    Status = GetLastError();
    if (Status != ERROR_INSUFFICIENT_BUFFER) {
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to get buffer size for device details: 0x%x", Status);
        goto end;
    }

    // Using 'BufferSize' from failed function call
#pragma warning(suppress: 6102)
    DetailData = (SP_DEVICE_INTERFACE_DETAIL_DATA *)malloc(BufferSize);
    if (!DetailData) {
        Status = ERROR_OUTOFMEMORY;
        goto end;
    }

    DetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

    if (!SetupDiGetDeviceInterfaceDetail(DevInfo, &InterfaceData, DetailData, BufferSize, NULL, NULL)) {
        Status = GetLastError();
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to get XENIFACE device path: 0x%x", Status);
        goto end;
    }

    Context->XenIface = CreateFile(DetailData->DevicePath,
                                   FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                   NULL);

    if (Context->XenIface == INVALID_HANDLE_VALUE) {
        Status = GetLastError();
        _Log(Logger, XLL_ERROR, Context->LogLevel, __FUNCTION__,
             L"Failed to open XENIFACE device (path: %s): 0x%x", DetailData->DevicePath, Status);
        goto end;
    }

    _Log(Logger, XLL_INFO, Context->LogLevel, __FUNCTION__,
         L"XenIface handle: %p", Context->XenIface);

    *Xc = Context;
     Status = ERROR_SUCCESS;

end:
    free(DetailData);

    if (Status != ERROR_SUCCESS) {
        free(Context);
        *Xc = NULL;
    }

    return Status;
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
    DWORD Status = ERROR_SUCCESS;

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
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND failed: 0x%x", Status);
        goto end;
    }

    *LocalPort = Out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %lu", *LocalPort);

end:
    return Status;
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
    DWORD Status = ERROR_SUCCESS;

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
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN failed: 0x%x", Status);
        goto end;
    }

    *LocalPort = Out.LocalPort;
    Log(XLL_DEBUG, L"LocalPort: %lu", *LocalPort);

end:
    return Status;
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
    DWORD Status = ERROR_SUCCESS;

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %lu", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_CLOSE,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_CLOSE failed: 0x%x", Status);
    }

    return Status;
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
    DWORD Status = ERROR_SUCCESS;

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %lu", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_NOTIFY,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_NOTIFY failed: 0x%x", Status);
    }

    return Status;
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
    DWORD Status = ERROR_SUCCESS;

    In.LocalPort = LocalPort;

    Log(XLL_DEBUG, L"LocalPort: %lu", LocalPort);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_EVTCHN_UNMASK,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_EVTCHN_UNMASK failed: 0x%x", Status);
    }

    return Status;
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
        goto end;

    Log(XLL_DEBUG, L"RemoteDomain: %d, Address %p, NumberPages: %lu, NotifyOffset: 0x%x, NotifyPort: %lu, Flags: 0x%x",
        RemoteDomain, Address, NumberPages, NotifyOffset, NotifyPort, Flags);

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_V2,
                              &In, sizeof(In),
                              Out, Size,
                              &Returned,
                              &Overlapped);

    // this IOCTL is expected to be pending on success
    if (!Success) {
        Status = GetLastError();
        if (Status != ERROR_IO_PENDING) {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_V2 failed: 0x%x", Status);
            goto end;
        }
        Status = ERROR_SUCCESS;
    } else {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_V2 not pending");
        Status = ERROR_UNIDENTIFIED_ERROR;
        goto end;
    }

    *SharedAddress = Out->Address;
    memcpy(References, &Out->References, NumberPages * sizeof(ULONG));
    Log(XLL_DEBUG, L"Address: %p", Out->Address);
#ifdef _DEBUG
    for (ULONG i = 0; i < NumberPages; i++)
        Log(XLL_DEBUG, L"Grant ref[%lu]: %lu", i, Out->References[i]);
#endif

end:
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
    DWORD Status = ERROR_SUCCESS;

    Log(XLL_DEBUG, L"Address: %p", Address);
    In.Address = Address;

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_V2,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_V2 failed: 0x%x", Status);
    }

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
    DWORD Status = ERROR_OUTOFMEMORY;

    Size = (ULONG)FIELD_OFFSET(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN_V2, References[NumberPages]);
    In = malloc(Size);
    if (!In)
        goto end;

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

    // this IOCTL is expected to be pending on success
    if (!Success) {
        Status = GetLastError();
        if (Status != ERROR_IO_PENDING) {
            Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_V2 failed: 0x%x", Status);
            goto end;
        }
        Status = ERROR_SUCCESS;
    } else {
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_V2 not pending");
        Status = ERROR_UNIDENTIFIED_ERROR;
        goto end;
    }

    *Address = Out.Address;

    Log(XLL_DEBUG, L"Address: %p", *Address);

end:
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
    DWORD Status = ERROR_SUCCESS;

    Log(XLL_DEBUG, L"Address: %p", Address);

    In.Address = Address;

    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_V2,
                              &In, sizeof(In),
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_V2 failed: 0x%x", Status);
    }

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
    DWORD Status = ERROR_SUCCESS;

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_READ,
                              Path, (DWORD)strlen(Path) + 1,
                              Value, cbValue,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_READ failed: 0x%x", Status);
        goto end;
    }

    Log(XLL_DEBUG, L"Value: '%S'", Value);

end:
    return Status;
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
    DWORD Status = ERROR_SUCCESS;

    cbBuffer = (DWORD)(strlen(Path) + 1 + strlen(Value) + 1 + 1);
    Buffer = malloc(cbBuffer);
    if (!Buffer) {
        Status = ERROR_OUTOFMEMORY;
        goto end;
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
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_WRITE failed: 0x%x", Status);
    }

    free(Buffer);

end:
    return Status;
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
    DWORD Status = ERROR_SUCCESS;

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_DIRECTORY,
                              Path, (DWORD)strlen(Path) + 1,
                              Output, cbOutput,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_DIRECTORY failed: 0x%x", Status);
        goto end;
    }

    _LogMultiSz(Xc, __FUNCTION__, XLL_DEBUG, Output);

end:
    return Status;
}

DWORD
XcStoreRemove(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path
    )
{
    DWORD Returned;
    BOOL Success;
    DWORD Status = ERROR_SUCCESS;

    Log(XLL_DEBUG, L"Path: '%S'", Path);
    Success = DeviceIoControl(Xc->XenIface,
                              IOCTL_XENIFACE_STORE_REMOVE,
                              Path, (DWORD)strlen(Path) + 1,
                              NULL, 0,
                              &Returned,
                              NULL);

    if (!Success) {
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_REMOVE failed: 0x%x", Status);
    }

    return Status;
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
    DWORD Status = ERROR_SUCCESS;
    XENIFACE_STORE_SET_PERMISSIONS_IN *In = NULL;

    Log(XLL_DEBUG, L"Path: '%S', Count: %lu", Path, Count);
    for (ULONG i = 0; i < Count; i++)
        Log(XLL_DEBUG, L"Domain: %d, Mask: 0x%x", Permissions[i].Domain, Permissions[i].Mask);

    Size = (ULONG)FIELD_OFFSET(XENIFACE_STORE_SET_PERMISSIONS_IN, Permissions[Count]);
    In = malloc(Size);
    if (!In) {
        Status = ERROR_OUTOFMEMORY;
        goto end;
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
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_SET_PERMISSIONS failed: 0x%x", Status);
    }

    free(In);
end:
    return Status;
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
    DWORD Status = ERROR_SUCCESS;
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
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_ADD_WATCH failed: 0x%x", Status);
        goto end;
    }

    *Handle = Out.Context;

    Log(XLL_DEBUG, L"Watch handle: %p", *Handle);

end:
    return Status;
}

DWORD
XcStoreRemoveWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Handle
    )
{
    DWORD Returned;
    BOOL Success;
    DWORD Status = ERROR_SUCCESS;
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
        Status = GetLastError();
        Log(XLL_ERROR, L"IOCTL_XENIFACE_STORE_REMOVE_WATCH failed: 0x%x", Status);
    }

    return Status;
}
