/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
 * Copyright (c) Rafal Wojdyla <omeg@invisiblethingslab.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#ifndef _IOCTLS_H_
#define _IOCTLS_H_

#include "xeniface_ioctls.h"

typedef struct _XENIFACE_STORE_CONTEXT {
    LIST_ENTRY             Entry;
    PCHAR                  Path;
    PXENIFACE_THREAD       Thread;
    PXENBUS_STORE_WATCH    Watch;
    PKEVENT                Event;
    PVOID                  FileObject;
} XENIFACE_STORE_CONTEXT, *PXENIFACE_STORE_CONTEXT;

typedef struct _XENIFACE_EVTCHN_CONTEXT {
    LIST_ENTRY             Entry;
    PXENBUS_EVTCHN_CHANNEL Channel;
    ULONG                  LocalPort;
    PKEVENT                Event;
    PXENIFACE_FDO          Fdo;
    KDPC                   Dpc;
    PVOID                  FileObject;
} XENIFACE_EVTCHN_CONTEXT, *PXENIFACE_EVTCHN_CONTEXT;

typedef struct _XENIFACE_SUSPEND_CONTEXT {
    LIST_ENTRY              Entry;
    PKEVENT                 Event;
    PVOID                   FileObject;
} XENIFACE_SUSPEND_CONTEXT, *PXENIFACE_SUSPEND_CONTEXT;

typedef enum _XENIFACE_GNTTAB_CONTEXT_TYPE {
    XENIFACE_GNTTAB_CONTEXT_GRANT = 1,
    XENIFACE_GNTTAB_CONTEXT_MAP
} XENIFACE_GNTTAB_CONTEXT_TYPE;

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union
typedef struct _XENIFACE_GNTTAB_CONTEXT {
    LIST_ENTRY                   Entry;
    XENIFACE_GNTTAB_CONTEXT_TYPE Type;
    BOOLEAN                      UseRequestId; // true for legacy IOCTLs
    ULONG                        RequestId;
    PEPROCESS                    Process;
    USHORT                       RemoteDomain;
    ULONG                        NumberPages;
    XENIFACE_GNTTAB_PAGE_FLAGS   Flags;
    ULONG                        NotifyOffset;
    ULONG                        NotifyPort;
    union {
        PXENBUS_GNTTAB_ENTRY     *Grants; // permit
        PHYSICAL_ADDRESS         Address; // map
    };
    PVOID                        KernelVa;
    PVOID                        UserVa;
    PMDL                         Mdl;
} XENIFACE_GNTTAB_CONTEXT, *PXENIFACE_GNTTAB_CONTEXT;
#pragma warning(pop)

NTSTATUS
__CaptureUserBuffer(
    _In_ PVOID      Buffer,
    _In_ ULONG      Length,
    _When_(Length != 0, _Outptr_result_bytebuffer_(Length))
    _When_(Length == 0, _Outptr_result_maybenull_)
    PVOID           *CapturedBuffer
    );

VOID
__FreeCapturedBuffer(
    _In_opt_ PVOID  CapturedBuffer
    );

NTSTATUS
XenIfaceIoctl(
    _In_ PXENIFACE_FDO  Fdo,
    _Inout_ PIRP        Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
XenIfaceCleanup(
    _In_ PXENIFACE_FDO      Fdo,
    _In_opt_ PFILE_OBJECT   FileObject
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRead(
    _In_ PXENIFACE_FDO  Fdo,
    _Inout_ PCHAR       Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _Out_ PULONG_PTR    Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreWrite(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PCHAR          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreDirectory(
    _In_ PXENIFACE_FDO  Fdo,
    _Inout_ PCHAR       Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _Out_ PULONG_PTR    Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRemove(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PCHAR          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreSetPermissions(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreAddWatch(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject,
    _Out_ PULONG_PTR    Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRemoveWatch(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
StoreFreeWatch(
    _In_ PXENIFACE_FDO              Fdo,
    _Inout_ PXENIFACE_STORE_CONTEXT Context
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindUnbound(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject,
    _Out_ PULONG_PTR    Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindInterdomain(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject,
    _Out_ PULONG_PTR    Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnClose(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnNotify(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnUnmask(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject
    );

_Requires_lock_not_held_(Fdo->EvtchnLock)
DECLSPEC_NOINLINE
NTSTATUS
EvtchnNotify(
    _In_ PXENIFACE_FDO      Fdo,
    _In_ ULONG              LocalPort,
    _In_opt_ PFILE_OBJECT   FileObject
    );

_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
EvtchnNotificationDpc(
    _In_ PKDPC      Dpc,
    _In_opt_ PVOID  Context,
    _In_opt_ PVOID  Argument1,
    _In_opt_ PVOID  Argument2
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EvtchnFree(
    _In_ PXENIFACE_FDO                  Fdo,
    _Inout_ PXENIFACE_EVTCHN_CONTEXT    Context
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabPermitForeignAccess(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _Inout_ PIRP        Irp
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabRevokeForeignAccess(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ ULONG          ControlCode
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabMapForeignPages(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _Inout_ PIRP        Irp
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabUnmapForeignPages(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ ULONG          ControlCode
    );

_Acquires_exclusive_lock_(((PXENIFACE_FDO)Argument)->GnttabCacheLock)
_IRQL_requires_(DISPATCH_LEVEL)
VOID
GnttabAcquireLock(
    _In_ PVOID  Argument
    );

_Releases_exclusive_lock_(((PXENIFACE_FDO)Argument)->GnttabCacheLock)
_IRQL_requires_(DISPATCH_LEVEL)
VOID
GnttabReleaseLock(
    _In_ PVOID  Argument
    );

_Function_class_(IO_WORKITEM_ROUTINE)
VOID
CompleteGnttabIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID      Context
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
GnttabFreeGrant(
    _In_ PXENIFACE_FDO                  Fdo,
    _Inout_ PXENIFACE_GNTTAB_CONTEXT    Context
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
GnttabFreeMap(
    _In_ PXENIFACE_FDO                  Fdo,
    _Inout_ PXENIFACE_GNTTAB_CONTEXT    Context
    );

NTSTATUS
IoctlSuspendGetCount(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PCHAR          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _Out_ PULONG_PTR    Info
    );

NTSTATUS
IoctlSuspendRegister(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject,
    _Out_ PULONG_PTR    Info
    );

NTSTATUS
IoctlSuspendDeregister(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PVOID          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _In_ PFILE_OBJECT   FileObject
    );

VOID
SuspendEventFire(
    _In_ PXENIFACE_FDO  Fdo
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
SuspendFreeEvent(
    _In_ PXENIFACE_FDO                  Fdo,
    _Inout_ PXENIFACE_SUSPEND_CONTEXT   Context
    );

NTSTATUS
IoctlSharedInfoGetTime(
    _In_ PXENIFACE_FDO  Fdo,
    _In_ PCHAR          Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen,
    _Out_ PULONG_PTR    Info
    );

NTSTATUS
IoctlLog(
    _In_ PXENIFACE_FDO  Fdo,
    _Inout_ PCHAR       Buffer,
    _In_ ULONG          InLen,
    _In_ ULONG          OutLen
    );

#endif // _IOCTLS_H_
