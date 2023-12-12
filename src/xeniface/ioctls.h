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
    __in  PVOID Buffer,
    __in  ULONG Length,
    __out PVOID *CapturedBuffer
    );

VOID
__FreeCapturedBuffer(
    __in_opt  PVOID CapturedBuffer
    );

NTSTATUS
XenIfaceIoctl(
    __in     PXENIFACE_FDO     Fdo,
    __inout  PIRP              Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
XenIfaceCleanup(
    __in  PXENIFACE_FDO Fdo,
    __in_opt  PFILE_OBJECT  FileObject
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRead(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreWrite(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreDirectory(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRemove(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreSetPermissions(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreAddWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRemoveWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
StoreFreeWatch(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_STORE_CONTEXT Context
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindUnbound(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindInterdomain(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnClose(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnNotify(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnUnmask(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    );

_Requires_lock_not_held_(Fdo->EvtchnLock)
DECLSPEC_NOINLINE
NTSTATUS
EvtchnNotify(
    __in      PXENIFACE_FDO Fdo,
    __in      ULONG         LocalPort,
    __in_opt  PFILE_OBJECT  FileObject
    );

_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
EvtchnNotificationDpc(
    __in      PKDPC Dpc,
    __in_opt  PVOID Context,
    __in_opt  PVOID Argument1,
    __in_opt  PVOID Argument2
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EvtchnFree(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_EVTCHN_CONTEXT Context
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabPermitForeignAccess(
    __in     PXENIFACE_FDO  Fdo,
    __in     PVOID          Buffer,
    __in     ULONG          InLen,
    __in     ULONG          OutLen,
    __inout  PIRP           Irp
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabRevokeForeignAccess(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  ULONG             ControlCode
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabMapForeignPages(
    __in     PXENIFACE_FDO     Fdo,
    __in     PVOID             Buffer,
    __in     ULONG             InLen,
    __in     ULONG             OutLen,
    __inout  PIRP              Irp
    );

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabUnmapForeignPages(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  ULONG             ControlCode
    );

_Acquires_exclusive_lock_(((PXENIFACE_FDO)Argument)->GnttabCacheLock)
_IRQL_requires_(DISPATCH_LEVEL)
VOID
GnttabAcquireLock(
    __in  PVOID Argument
    );

_Releases_exclusive_lock_(((PXENIFACE_FDO)Argument)->GnttabCacheLock)
_IRQL_requires_(DISPATCH_LEVEL)
VOID
GnttabReleaseLock(
    __in  PVOID Argument
    );

_Function_class_(IO_WORKITEM_ROUTINE)
VOID
CompleteGnttabIrp(
    __in      PDEVICE_OBJECT DeviceObject,
    __in_opt  PVOID          Context
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
GnttabFreeGrant(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_GNTTAB_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
GnttabFreeMap(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_GNTTAB_CONTEXT Context
    );

NTSTATUS
IoctlSuspendGetCount(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    );

NTSTATUS
IoctlSuspendRegister(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    );

NTSTATUS
IoctlSuspendDeregister(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    );

VOID
SuspendEventFire(
    __in    PXENIFACE_FDO   Fdo
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
SuspendFreeEvent(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_SUSPEND_CONTEXT Context
    );

NTSTATUS
IoctlSharedInfoGetTime(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    );

NTSTATUS
IoctlLog(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    );

#endif // _IOCTLS_H_
