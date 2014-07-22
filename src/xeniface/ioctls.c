/* Copyright (c) Citrix Systems Inc.
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
#include "..\..\include\xeniface_ioctls.h"
#include "log.h"

static FORCEINLINE BOOLEAN
__IsValidStr(
    __in  PCHAR             Str,
    __in  ULONG             Len
    )
{
    for ( ; Len--; ++Str) {
        if (*Str == '\0')
            return TRUE;
        if (!isprint((unsigned char)*Str))
            break;
    }
    return FALSE;
}
static FORCEINLINE ULONG
__MultiSzLen(
    __in  PCHAR             Str,
    __out PULONG            Count
    )
{
    ULONG Length = 0;
    if (Count)  *Count = 0;
    do {
        for ( ; *Str; ++Str, ++Length) ;
        ++Str; ++Length;
        if (*Count) ++(*Count);
    } while (*Str);
    return Length;
}
static FORCEINLINE VOID
__DisplayMultiSz(
    __in PCHAR              Caller,
    __in PCHAR              Str
    )
{
    PCHAR   Ptr;
    ULONG   Idx;
    ULONG   Len;

    for (Ptr = Str, Idx = 0; *Ptr; ++Idx) {
        Len = (ULONG)strlen(Ptr);
        XenIfaceDebugPrint(INFO, "|%s: [%d]=(%d)->\"%s\"\n", Caller, Idx, Len, Ptr);
        Ptr += (Len + 1);
    }
}


static DECLSPEC_NOINLINE NTSTATUS
IoctlRead(
    __in  PXENIFACE_FDO         Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Read, &Fdo->StoreInterface, NULL, NULL, Buffer, &Value);
    if (!NT_SUCCESS(status))
        goto fail3;

    Length = (ULONG)strlen(Value) + 1;

    status = STATUS_BUFFER_OVERFLOW;
    if (OutLen == 0) {
        XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)\n", __FUNCTION__, Buffer, Length);
        goto done;
    } 
    
    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)->\"%s\"\n", __FUNCTION__, Buffer, Length, Value);

    RtlCopyMemory(Buffer, Value, Length);
    Buffer[Length - 1] = 0;
    status = STATUS_SUCCESS;

done:
    *Info = (ULONG_PTR)Length;
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "|%s: Fail4 (\"%s\")=(%d < %d)\n", __FUNCTION__, Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlWrite(
    __in  PXENIFACE_FDO         Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0 || OutLen != 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    Length = (ULONG)strlen(Buffer) + 1;
    Value = Buffer + Length;

    if (!__IsValidStr(Value, InLen - Length))
        goto fail3;

    status = XENBUS_STORE(Printf, &Fdo->StoreInterface, NULL, NULL, Buffer, Value);
    if (!NT_SUCCESS(status))
        goto fail4;

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\"=\"%s\")\n", __FUNCTION__, Buffer, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "|%s: Fail4 (\"%s\")\n", __FUNCTION__, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlDirectory(
    __in  PXENIFACE_FDO         Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;
    ULONG       Count;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Directory, &Fdo->StoreInterface, NULL, NULL, Buffer, &Value);
    if (!NT_SUCCESS(status))
        goto fail3;

    Length = __MultiSzLen(Value, &Count) + 1;

    status = STATUS_BUFFER_OVERFLOW;
    if (OutLen == 0) {
        XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)(%d)\n", __FUNCTION__, Buffer, Length, Count);
        goto done;
    } 

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\")=(%d)(%d)\n", __FUNCTION__, Buffer, Length, Count);
#if DBG
    __DisplayMultiSz(__FUNCTION__, Value);
#endif

    RtlCopyMemory(Buffer, Value, Length);
    Buffer[Length - 2] = 0;
    Buffer[Length - 1] = 0;
    status = STATUS_SUCCESS;

done:
    *Info = (ULONG_PTR)Length;
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
    return status;

fail4:
    XenIfaceDebugPrint(ERROR, "|%s: Fail4 (\"%s\")=(%d < %d)\n", __FUNCTION__, Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
IoctlRemove(
    __in  PXENIFACE_FDO         Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS    status;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0 || OutLen != 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Remove, &Fdo->StoreInterface, NULL, NULL, Buffer);
    if (!NT_SUCCESS(status))
        goto fail3;

    XenIfaceDebugPrint(INFO, "|%s: (\"%s\")\n", __FUNCTION__, Buffer);
    return status;

fail3:
    XenIfaceDebugPrint(ERROR, "|%s: Fail3 (\"%s\")\n", __FUNCTION__, Buffer);
fail2:
    XenIfaceDebugPrint(ERROR, "|%s: Fail2\n", __FUNCTION__);
fail1:
    XenIfaceDebugPrint(ERROR, "|%s: Fail1 (%08x)\n", __FUNCTION__, status);
    return status;
}

NTSTATUS
XenIFaceIoctl(
    __in  PXENIFACE_FDO         Fdo,
    __in  PIRP              Irp
    )
{
    NTSTATUS            status;
    PIO_STACK_LOCATION  Stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID               Buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG               InLen = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG               OutLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    status = STATUS_DEVICE_NOT_READY;
    if (Fdo->InterfacesAcquired == FALSE)
        goto done;

    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_XENIFACE_STORE_READ:
        status = IoctlRead(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_WRITE:
        status = IoctlWrite(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_STORE_DIRECTORY:
        status = IoctlDirectory(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_REMOVE:
        status = IoctlRemove(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

done:

	Irp->IoStatus.Status = status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

