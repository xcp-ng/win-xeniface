/* Copyright (c) Rafal Wojdyla <omeg@invisiblethingslab.com>
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

#include "driver.h"
#include "ioctls.h"
#include "xeniface_ioctls.h"
#include "log.h"
#include "irp_queue.h"
#include "util.h"

// Complete a canceled gnttab IRP, cleanup associated grant/map.
_Function_class_(IO_WORKITEM_ROUTINE)
VOID
CompleteGnttabIrp(
    __in      PDEVICE_OBJECT DeviceObject,
    __in_opt  PVOID          Context
    )
{
    PXENIFACE_DX Dx = (PXENIFACE_DX)DeviceObject->DeviceExtension;
    PXENIFACE_FDO Fdo = Dx->Fdo;
    PIRP Irp = Context;
    PXENIFACE_GNTTAB_CONTEXT GnttabContext;
    PIO_WORKITEM WorkItem;
    KAPC_STATE ApcState;
    BOOLEAN ChangeProcess;

    ASSERT(Context != NULL);

    GnttabContext = Irp->Tail.Overlay.DriverContext[0];
    WorkItem = Irp->Tail.Overlay.DriverContext[1];

    // We are not guaranteed to be in the context of the process that initiated the IRP,
    // but we need to be there to unmap memory.
    ChangeProcess = PsGetCurrentProcess() != GnttabContext->Process;
    if (ChangeProcess) {
        Trace("Changing process from %p to %p\n", PsGetCurrentProcess(), GnttabContext->Process);
        KeStackAttachProcess(GnttabContext->Process, &ApcState);
    }

    Trace("Irp %p, Process %p, Id %lu, Type %d, IRQL %d\n",
          Irp, GnttabContext->Process, GnttabContext->RequestId, GnttabContext->Type, KeGetCurrentIrql());

    switch (GnttabContext->Type) {

    case XENIFACE_GNTTAB_CONTEXT_GRANT:
        GnttabFreeGrant(Fdo, GnttabContext);
        break;

    case XENIFACE_GNTTAB_CONTEXT_MAP:
        GnttabFreeMap(Fdo, GnttabContext);
        break;

    default:
        ASSERT(FALSE);
    }

    if (ChangeProcess)
        KeUnstackDetachProcess(&ApcState);

    IoFreeWorkItem(WorkItem);

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

_Acquires_exclusive_lock_(((PXENIFACE_FDO)Argument)->GnttabCacheLock)
_IRQL_requires_(DISPATCH_LEVEL)
VOID
GnttabAcquireLock(
    __in  PVOID Argument
    )
{
    PXENIFACE_FDO Fdo = Argument;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Fdo->GnttabCacheLock);
}

_Releases_exclusive_lock_(((PXENIFACE_FDO)Argument)->GnttabCacheLock)
_IRQL_requires_(DISPATCH_LEVEL)
VOID
GnttabReleaseLock(
    __in  PVOID Argument
    )
{
    PXENIFACE_FDO Fdo = Argument;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    KeReleaseSpinLockFromDpcLevel(&Fdo->GnttabCacheLock);
}

_Requires_lock_not_held_(Fdo->IrpQueueLock)
static
PIRP
FindGnttabIrp(
    __in  PXENIFACE_FDO Fdo,
    __in  PXENIFACE_GNTTAB_CONTEXT Context
    )
{
    KIRQL Irql;
    PIRP Irp;

    CsqAcquireLock(&Fdo->IrpQueue, &Irql);
    Irp = CsqPeekNextIrp(&Fdo->IrpQueue, NULL, Context);
    CsqReleaseLock(&Fdo->IrpQueue, Irql);
    return Irp;
}

// Undo (possibly partially done) sharing, free/clear associated context fields.
// Does not trigger notifications if the flags are set.
static
void
GnttabStopSharing(
    __in     PXENIFACE_FDO             Fdo,
    __inout  PXENIFACE_GNTTAB_CONTEXT  Context,
    __in     ULONG                     NumberPages
)
{
    if (Context->Grants != NULL) {
        for (ULONG Page = 0; Page < NumberPages; Page++) {
            ASSERT(NT_SUCCESS(XENBUS_GNTTAB(RevokeForeignAccess,
                                            &Fdo->GnttabInterface,
                                            Fdo->GnttabCache,
                                            FALSE,
                                            Context->Grants[Page])));
        }

        RtlZeroMemory(Context->Grants, Context->NumberPages * sizeof(Context->Grants[0]));
        __FreePoolWithTag(Context->Grants, XENIFACE_POOL_TAG);
        Context->Grants = NULL;
    }

    if (Context->Mdl != NULL) {
        if (Context->KernelVa != NULL) {
            // driver-allocated memory
            MmUnmapLockedPages(Context->UserVa, Context->Mdl);
        } else {
            // user-supplied memory
            try {
                MmUnlockPages(Context->Mdl);
            } except(EXCEPTION_EXECUTE_HANDLER) {
                Error("Failed to unlock user pages: 0x%x\n", GetExceptionCode());
                // this shouldn't happen and will BSOD the system when the user process exits with locked pages
            }
        }

        IoFreeMdl(Context->Mdl);
        Context->Mdl = NULL;
    }

    if (Context->KernelVa != NULL) {
        __FreePoolWithTag(Context->KernelVa, XENIFACE_POOL_TAG);
        Context->KernelVa = NULL;
    }
}

static
NTSTATUS
GnttabPermitForeignAccess(
    __in     PXENIFACE_FDO             Fdo,
    __inout  PXENIFACE_GNTTAB_CONTEXT  Context
    )
{
    NTSTATUS Status;
    ULONG Page = 0;
    size_t GrantsSize = 0;
    ULONG SharedSize = 0;

    Trace("> RemoteDomain %d, UserVa %p, NumberPages %lu, Flags 0x%x, Offset 0x%x, Port %d, Process %p, Id %lu\n",
          Context->RemoteDomain, Context->UserVa, Context->NumberPages, Context->Flags,
          Context->NotifyOffset, Context->NotifyPort, Context->Process, Context->RequestId);

    // Check if the request ID/address is unique for this process.
    // This doesn't protect us from simultaneous requests with the same ID arriving here
    // but another check for duplicate ID is performed when the context/IRP is queued at the end.
    // Ideally we would lock the whole section but that's not really an option since we touch user memory.
    Status = STATUS_INVALID_PARAMETER;
    if (FindGnttabIrp(Fdo, Context) != NULL)
        goto fail1;

    GrantsSize = Context->NumberPages * sizeof(PXENBUS_GNTTAB_ENTRY);
    SharedSize = Context->NumberPages * PAGE_SIZE;
    Status = STATUS_NO_MEMORY;
    Context->Grants = __AllocatePoolWithTag(NonPagedPool, GrantsSize, XENIFACE_POOL_TAG);
    if (Context->Grants == NULL)
        goto fail2;

    if (Context->UserVa == NULL) {
        // sharing driver-allocated pages
        Status = STATUS_NO_MEMORY;
        Context->KernelVa = __AllocatePoolWithTag(NonPagedPool, SharedSize, XENIFACE_POOL_TAG);
        if (Context->KernelVa == NULL)
            goto fail3;

        Context->Mdl = IoAllocateMdl(Context->KernelVa, SharedSize, FALSE, FALSE, NULL);
        if (Context->Mdl == NULL)
            goto fail4;

        MmBuildMdlForNonPagedPool(Context->Mdl);
        ASSERT(MmGetMdlByteCount(Context->Mdl) == SharedSize);
    } else {
        // sharing existing memory
        Context->KernelVa = NULL;
        Context->Mdl = IoAllocateMdl(Context->UserVa, SharedSize, FALSE, FALSE, NULL);
        if (Context->Mdl == NULL)
            goto fail4;

        try {
            MmProbeAndLockPages(Context->Mdl,
                                UserMode,
                                (Context->Flags & XENIFACE_GNTTAB_READONLY) != 0 ? IoReadAccess : IoWriteAccess);
        } except(EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
            Error("Failed to lock user pages: 0x%x\n", Status);
            Page = 0;
            goto fail5;
        }
    }

    // perform sharing
    for (Page = 0; Page < Context->NumberPages; Page++) {
        Status = XENBUS_GNTTAB(PermitForeignAccess,
                               &Fdo->GnttabInterface,
                               Fdo->GnttabCache,
                               FALSE,
                               Context->RemoteDomain,
                               MmGetMdlPfnArray(Context->Mdl)[Page],
                               (Context->Flags & XENIFACE_GNTTAB_READONLY) != 0,
                               &(Context->Grants[Page]));
#if DBG
        Info("Grants[%lu] = %p\n", Page, Context->Grants[Page]);
#endif
        if (!NT_SUCCESS(Status))
            goto fail5;
    }

    if (Context->KernelVa != NULL) {
        // map driver-allocated memory into user mode
#pragma prefast(suppress:6320) // we want to catch all exceptions
        try {
            Context->UserVa = MmMapLockedPagesSpecifyCache(Context->Mdl,
                                                           UserMode,
                                                           MmCached,
                                                           NULL,
                                                           FALSE,
                                                           NormalPagePriority);
        } except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
            goto fail6;
        }
    }

    Trace("< Context %p, KernelVa %p, UserVa %p\n",
          Context, Context->KernelVa, Context->UserVa);

    return STATUS_SUCCESS;

fail6:
    Error("Fail6\n");

fail5:
    Error("Fail5\n");

fail4:
    Error("Fail4\n");

fail3:
    Error("Fail3\n");

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1\n");
    GnttabStopSharing(Fdo, Context, Page);

    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(*Context));
        __FreePoolWithTag(Context, XENIFACE_POOL_TAG);
    }

    return Status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabPermitForeignAccess(
    __in     PXENIFACE_FDO  Fdo,
    __in     PVOID          Buffer,
    __in     ULONG          InLen,
    __in     ULONG          OutLen,
    __inout  PIRP           Irp
    )
{
    NTSTATUS Status;
    PXENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN In1 = NULL;
    PXENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN_V2 In = NULL;
    // XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT_V2 is the same as XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT
    PXENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT Out = Irp->UserBuffer;
    PXENIFACE_GNTTAB_CONTEXT Context;
    ULONG Page;
    ULONG ControlCode = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;

    Status = STATUS_INVALID_BUFFER_SIZE;
    if ((InLen != sizeof(XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN) && ControlCode == IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS)
        || (InLen != sizeof(XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN_V2) && ControlCode == IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_V2))
        goto fail1;

    // This IOCTL uses METHOD_NEITHER so we directly access user memory.
    if (ControlCode == IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS) {
        // legacy IOCTL, convert the input to v2
        Status = __CaptureUserBuffer(Buffer, InLen, &In1);
        if (!NT_SUCCESS(Status))
            goto fail2;

        Status = STATUS_NO_MEMORY;
        In = __AllocatePoolWithTag(NonPagedPool, sizeof(*In), XENIFACE_POOL_TAG);
        if (!In)
            goto fail3;

        In->RemoteDomain = In1->RemoteDomain;
        In->Address = NULL;
        In->NumberPages = In->NumberPages;
        In->Flags = In1->Flags;
        In->NotifyOffset = In1->NotifyOffset;
        In->NotifyPort = In1->NotifyPort;
    } else {
        Status = __CaptureUserBuffer(Buffer, InLen, &In);
        if (!NT_SUCCESS(Status))
            goto fail2;
    }

    Status = STATUS_INVALID_PARAMETER;
    if (In->NumberPages == 0 || In->NumberPages > 1024 * 1024) {
        goto fail4;
    }

    if ((In->Flags & XENIFACE_GNTTAB_USE_NOTIFY_OFFSET) &&
        (In->NotifyOffset >= In->NumberPages * PAGE_SIZE)) {
        goto fail5;
    }

    Status = STATUS_INVALID_BUFFER_SIZE;
    if (OutLen != (ULONG)FIELD_OFFSET(XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT, References[In->NumberPages]))
        goto fail6;

    Status = STATUS_NO_MEMORY;
    Context = __AllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_GNTTAB_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail7;

    Context->Type = XENIFACE_GNTTAB_CONTEXT_GRANT;
    Context->Process = PsGetCurrentProcess();
    Context->RemoteDomain = In->RemoteDomain;
    Context->UserVa = In->Address;
    Context->NumberPages = In->NumberPages;
    Context->Flags = In->Flags;
    Context->NotifyOffset = In->NotifyOffset;
    Context->NotifyPort = In->NotifyPort;

    __FreeCapturedBuffer(In);
    In = NULL;

    if (ControlCode == IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS) {
        Context->UseRequestId = TRUE;
        Context->RequestId = In1->RequestId;
        __FreeCapturedBuffer(In1);
        In1 = NULL;
    } else {
        Context->UseRequestId = FALSE;
        Context->RequestId = 0;
    }

    Status = GnttabPermitForeignAccess(Fdo, Context);
    if (!NT_SUCCESS(Status))
        goto fail8;

    Trace("< Context %p, Irp %p, KernelVa %p, UserVa %p\n",
          Context, Irp, Context->KernelVa, Context->UserVa);

    // Pass the result to user mode.
#pragma prefast(suppress: 6320) // we want to catch all exceptions
    try {
        ProbeForWrite(Out, OutLen, 1);
        Out->Address = Context->UserVa;

        for (Page = 0; Page < Context->NumberPages; Page++) {
            Out->References[Page] = XENBUS_GNTTAB(GetReference,
                                                  &Fdo->GnttabInterface,
                                                  Context->Grants[Page]);
        }
    } except(EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        Error("Exception 0x%lx while probing/writing output buffer at %p, size 0x%lx\n", Status, Out, OutLen);
        goto fail9;
    }

    // Insert the IRP/context into the pending queue.
    // This also checks (again) if the request ID/address is unique for the calling process.
    Irp->Tail.Overlay.DriverContext[0] = Context;
    Status = IoCsqInsertIrpEx(&Fdo->IrpQueue, Irp, NULL, Context);
    if (!NT_SUCCESS(Status))
        goto fail10;

    return STATUS_PENDING;

fail10:
    Error("Fail10\n");

fail9:
    Error("Fail9\n");
    GnttabStopSharing(Fdo, Context, Context->NumberPages);

fail8:
    Error("Fail8\n");
    RtlZeroMemory(Context, sizeof(*Context));
    __FreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail7:
    Error("Fail7\n");

fail6:
    Error("Fail6\n");

fail5:
    Error("Fail5\n");

fail4:
    Error("Fail4\n");
    __FreeCapturedBuffer(In);

fail3:
    Error("Fail3\n");
    __FreeCapturedBuffer(In1); // NULL-safe

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
GnttabFreeGrant(
    __in     PXENIFACE_FDO             Fdo,
    __inout  PXENIFACE_GNTTAB_CONTEXT  Context
)
{
    NTSTATUS status;

    Trace("Context %p\n", Context);

    ASSERT(Context->Type == XENIFACE_GNTTAB_CONTEXT_GRANT);
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (Context->Flags & XENIFACE_GNTTAB_USE_NOTIFY_OFFSET) {
        ((PCHAR)Context->KernelVa)[Context->NotifyOffset] = 0;
    }

    if (Context->Flags & XENIFACE_GNTTAB_USE_NOTIFY_PORT) {
        status = EvtchnNotify(Fdo, Context->NotifyPort, NULL);

        if (!NT_SUCCESS(status)) // non-fatal, we must free memory
            Error("failed to notify port %lu: 0x%x\n", Context->NotifyPort, status);
    }

    GnttabStopSharing(Fdo, Context, Context->NumberPages);

    RtlZeroMemory(Context, sizeof(*Context));
    __FreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabRevokeForeignAccess(
    __in  PXENIFACE_FDO  Fdo,
    __in  PVOID          Buffer,
    __in  ULONG          InLen,
    __in  ULONG          OutLen,
    __in  ULONG          ControlCode
    )
{
    NTSTATUS Status;
    XENIFACE_GNTTAB_CONTEXT SeekContext;
    PIRP PendingIrp;
    PXENIFACE_GNTTAB_CONTEXT Context = NULL;

    UNREFERENCED_PARAMETER(OutLen);

    Status = STATUS_INVALID_BUFFER_SIZE;

    SeekContext.Type = XENIFACE_GNTTAB_CONTEXT_GRANT;
    SeekContext.Process = PsGetCurrentProcess();

    if (ControlCode == IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS) {
        if (InLen != sizeof(XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN))
            goto fail1;

        SeekContext.UseRequestId = TRUE;
        SeekContext.RequestId = ((PXENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN)Buffer)->RequestId;
        Trace("> Process %p, Id %lu\n", SeekContext.Process, SeekContext.RequestId);
    } else {
        if (InLen != sizeof(XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN_V2))
            goto fail1;

        SeekContext.UseRequestId = FALSE;
        SeekContext.UserVa = ((PXENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN_V2)Buffer)->Address;
        Trace("> Process %p, Address %p\n", SeekContext.Process, SeekContext.UserVa);
    }

    Status = STATUS_NOT_FOUND;
    PendingIrp = IoCsqRemoveNextIrp(&Fdo->IrpQueue, &SeekContext);
    if (PendingIrp == NULL)
        goto fail2;

    Context = PendingIrp->Tail.Overlay.DriverContext[0];
    GnttabFreeGrant(Fdo, Context);

    PendingIrp->IoStatus.Status = STATUS_SUCCESS;
    PendingIrp->IoStatus.Information = 0;
    IoCompleteRequest(PendingIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabMapForeignPages(
    __in     PXENIFACE_FDO  Fdo,
    __in     PVOID          Buffer,
    __in     ULONG          InLen,
    __in     ULONG          OutLen,
    __inout  PIRP           Irp
    )
{
    NTSTATUS status;
    PXENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN In1 = NULL;
    PXENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN_V2 In = NULL;
    // XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT_V2 is the same as XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT
    PXENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT Out = Irp->UserBuffer;
    ULONG NumberPages;
    PXENIFACE_GNTTAB_CONTEXT Context;
    ULONG ControlCode = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;

    ASSERT(ControlCode == IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES || ControlCode == IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_V2);

    status = STATUS_NO_MEMORY;
    Context = __AllocatePoolWithTag(NonPagedPool, sizeof(*Context), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail1;

    Context->Type = XENIFACE_GNTTAB_CONTEXT_MAP;
    Context->Process = PsGetCurrentProcess();

    // This IOCTL uses METHOD_NEITHER so we directly access user memory.
    if (ControlCode == IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES) {
        status = STATUS_INVALID_BUFFER_SIZE;
        if (InLen < sizeof(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN)
            || OutLen != sizeof(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT))
            goto fail2;

        In1 = Buffer;
        NumberPages = (InLen - (ULONG)FIELD_OFFSET(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN, References)) / sizeof(ULONG);
        status = __CaptureUserBuffer(Buffer, InLen, &In1);
        if (!NT_SUCCESS(status))
            goto fail3;

        Context->UseRequestId = TRUE;
        Context->RequestId = In1->RequestId;

        // legacy IOCTL, convert the input to v2
        status = STATUS_NO_MEMORY;
        In = __AllocatePoolWithTag(NonPagedPool, sizeof(*In), XENIFACE_POOL_TAG);
        if (In == NULL)
            goto fail4;

        In->RemoteDomain = In1->RemoteDomain;
        In->NumberPages = In1->NumberPages;
        In->NotifyOffset = In1->NotifyOffset;
        In->NotifyPort = In1->NotifyPort;
        In->Flags = In1->Flags;
        memcpy(&In->References, &In1->References, NumberPages * sizeof(ULONG));

        __FreeCapturedBuffer(In1);
        In1 = NULL;
    } else {
        status = STATUS_INVALID_BUFFER_SIZE;
        if (InLen < sizeof(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN_V2)
            || OutLen != sizeof(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT_V2))
            goto fail2;

        In = Buffer;
        NumberPages = (InLen - (ULONG)FIELD_OFFSET(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN_V2, References)) / sizeof(ULONG);
        status = __CaptureUserBuffer(Buffer, InLen, &In);
        if (!NT_SUCCESS(status))
            goto fail3;

        Context->UseRequestId = FALSE;
        Context->RequestId = 0;
    }

    // At this point we only access In.
    status = STATUS_INVALID_PARAMETER;
    if (In->NumberPages == 0 ||
        In->NumberPages > 1024 * 1024 ||
        In->NumberPages != NumberPages) {
        goto fail5;
    }

    if ((In->Flags & XENIFACE_GNTTAB_USE_NOTIFY_OFFSET) &&
        (In->NotifyOffset >= In->NumberPages * PAGE_SIZE)) {
        goto fail6;
    }

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != (ULONG)FIELD_OFFSET(XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN_V2, References[In->NumberPages]))
        goto fail7;

    Context->RemoteDomain = In->RemoteDomain;
    Context->NumberPages = In->NumberPages;
    Context->Flags = In->Flags;
    Context->NotifyOffset = In->NotifyOffset;
    Context->NotifyPort = In->NotifyPort;

    Trace("> RemoteDomain %d, NumberPages %lu, Flags 0x%x, Offset 0x%x, Port %d, Process %p, Id %lu\n",
          Context->RemoteDomain, Context->NumberPages, Context->Flags, Context->NotifyOffset, Context->NotifyPort,
          Context->Process, Context->RequestId);

#if DBG
    for (ULONG PageIndex = 0; PageIndex < In->NumberPages; PageIndex++)
        Info("> Ref %d\n", In->References[PageIndex]);
#endif

    status = STATUS_INVALID_PARAMETER;
    if (FindGnttabIrp(Fdo, Context) != NULL)
        goto fail8;

    status = XENBUS_GNTTAB(MapForeignPages,
                           &Fdo->GnttabInterface,
                           Context->RemoteDomain,
                           Context->NumberPages,
                           In->References,
                           Context->Flags & XENIFACE_GNTTAB_READONLY,
                           &Context->Address);

    if (!NT_SUCCESS(status))
        goto fail9;

    status = STATUS_INSUFFICIENT_RESOURCES;
    Context->KernelVa = MmMapIoSpace(Context->Address, Context->NumberPages * PAGE_SIZE, MmCached);
    if (Context->KernelVa == NULL)
        goto fail10;

    status = STATUS_NO_MEMORY;
    Context->Mdl = IoAllocateMdl(Context->KernelVa, Context->NumberPages * PAGE_SIZE, FALSE, FALSE, NULL);
    if (Context->Mdl == NULL)
        goto fail11;

    MmBuildMdlForNonPagedPool(Context->Mdl);

    // map into user mode
#pragma prefast(suppress: 6320) // we want to catch all exceptions
    try {
        Context->UserVa = MmMapLockedPagesSpecifyCache(Context->Mdl,
                                                       UserMode,
                                                       MmCached,
                                                       NULL,
                                                       FALSE,
                                                       NormalPagePriority);
    } except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto fail12;
    }

    Trace("< Context %p, Irp %p, Address %p, KernelVa %p, UserVa %p\n",
          Context, Irp, Context->Address, Context->KernelVa, Context->UserVa);

    // Pass the result to user mode.
#pragma prefast(suppress: 6320) // we want to catch all exceptions
    try {
        ProbeForWrite(Out, OutLen, 1);
        Out->Address = Context->UserVa;
    } except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        Error("Exception 0x%lx while probing/writing output buffer at %p, size 0x%lx\n", status, Out, OutLen);
        goto fail13;
    }

    // Insert the IRP/context into the pending queue.
    // This also checks (again) if the request ID is unique for the calling process.
    Irp->Tail.Overlay.DriverContext[0] = Context;
    status = IoCsqInsertIrpEx(&Fdo->IrpQueue, Irp, NULL, Context);
    if (!NT_SUCCESS(status))
        goto fail14;

    __FreeCapturedBuffer(In);

    return STATUS_PENDING;

fail14:
    Error("Fail14\n");

fail13:
    Error("Fail13\n");
    MmUnmapLockedPages(Context->UserVa, Context->Mdl);

fail12:
    Error("Fail12\n");
    IoFreeMdl(Context->Mdl);

fail11:
    Error("Fail11\n");
    MmUnmapIoSpace(Context->KernelVa, Context->NumberPages * PAGE_SIZE);

fail10:
    Error("Fail10\n");
    ASSERT(NT_SUCCESS(XENBUS_GNTTAB(UnmapForeignPages,
                                    &Fdo->GnttabInterface,
                                    Context->Address
                                    )));

fail9:
    Error("Fail9\n");

fail8:
    Error("Fail8\n");

fail7:
    Error("Fail7\n");

fail6:
    Error("Fail6\n");

fail5:
    Error("Fail5\n");
    __FreeCapturedBuffer(In);

fail4:
    Error("Fail4\n");
    __FreeCapturedBuffer(In1);

fail3:
    Error("Fail3\n");

fail2:
    Error("Fail2\n");
    RtlZeroMemory(Context, sizeof(*Context));
    __FreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
DECLSPEC_NOINLINE
VOID
GnttabFreeMap(
    __in     PXENIFACE_FDO             Fdo,
    __inout  PXENIFACE_GNTTAB_CONTEXT  Context
    )
{
    NTSTATUS status;

    ASSERT(Context->Type == XENIFACE_GNTTAB_CONTEXT_MAP);
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    Trace("Context %p\n", Context);

    if (Context->Flags & XENIFACE_GNTTAB_USE_NOTIFY_OFFSET) {
        ((PCHAR)Context->KernelVa)[Context->NotifyOffset] = 0;
    }

    if (Context->Flags & XENIFACE_GNTTAB_USE_NOTIFY_PORT) {
        status = EvtchnNotify(Fdo, Context->NotifyPort, NULL);

        if (!NT_SUCCESS(status)) // non-fatal, we must free memory
            Error("failed to notify port %lu: 0x%x\n", Context->NotifyPort, status);
    }

    // unmap from user address space
    MmUnmapLockedPages(Context->UserVa, Context->Mdl);

    IoFreeMdl(Context->Mdl);

    // unmap from system space
    MmUnmapIoSpace(Context->KernelVa, Context->NumberPages * PAGE_SIZE);

    // undo mapping
    status = XENBUS_GNTTAB(UnmapForeignPages,
                           &Fdo->GnttabInterface,
                           Context->Address);

    ASSERT(NT_SUCCESS(status));

    RtlZeroMemory(Context, sizeof(*Context));
    __FreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlGnttabUnmapForeignPages(
    __in  PXENIFACE_FDO  Fdo,
    __in  PVOID          Buffer,
    __in  ULONG          InLen,
    __in  ULONG          OutLen,
    __in  ULONG          ControlCode
    )
{
    NTSTATUS status;
    XENIFACE_GNTTAB_CONTEXT SeekContext;
    PXENIFACE_GNTTAB_CONTEXT Context;
    PIRP PendingIrp;

    ASSERT(ControlCode == IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES
        || ControlCode == IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_V2);

    SeekContext.Type = XENIFACE_GNTTAB_CONTEXT_MAP;
    SeekContext.Process = PsGetCurrentProcess();

    if (ControlCode == IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES) {
        status = STATUS_INVALID_BUFFER_SIZE;
        if (InLen != sizeof(XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN) || OutLen != 0) {
            goto fail1;
        }

        PXENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN In = Buffer;
        SeekContext.UseRequestId = TRUE;
        SeekContext.RequestId = In->RequestId;

        Trace("> Process %p, Id %lu\n", SeekContext.Process, SeekContext.RequestId);
    } else {
        status = STATUS_INVALID_BUFFER_SIZE;
        if (InLen != sizeof(XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN_V2) || OutLen != 0) {
            goto fail1;
        }

        PXENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN_V2 In = Buffer;
        SeekContext.UseRequestId = FALSE;
        SeekContext.UserVa = In->Address;

        Trace("> Process %p, UserVa %p\n", SeekContext.Process, SeekContext.UserVa);
    }

    status = STATUS_NOT_FOUND;
    PendingIrp = IoCsqRemoveNextIrp(&Fdo->IrpQueue, &SeekContext);
    if (PendingIrp == NULL)
        goto fail2;

    Context = PendingIrp->Tail.Overlay.DriverContext[0];
    GnttabFreeMap(Fdo, Context);

    PendingIrp->IoStatus.Status = STATUS_SUCCESS;
    PendingIrp->IoStatus.Information = 0;
    IoCompleteRequest(PendingIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}
