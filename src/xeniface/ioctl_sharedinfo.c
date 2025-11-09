/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
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

#include <limits.h>

#include "driver.h"
#include "ioctls.h"
#include "xeniface_ioctls.h"
#include "log.h"

DECLSPEC_NOINLINE
NTSTATUS
IoctlSharedInfoGetTime(
    __in  PXENIFACE_FDO                 Fdo,
    __in  PCHAR                         Buffer,
    __in  ULONG                         InLen,
    __in  ULONG                         OutLen,
    __inout  PIRP                       Irp
    )
{
    LARGE_INTEGER                       Time;
    LARGE_INTEGER                       Offset;
    ULONG                               Flags;
    ULONG                               ControlCode;
    NTSTATUS                            status;

    ControlCode = IoGetCurrentIrpStackLocation(Irp)->
        Parameters.DeviceIoControl.IoControlCode;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != 0)
        goto fail1;

    if ((ControlCode == IOCTL_XENIFACE_SHAREDINFO_GET_TIME &&
         OutLen != sizeof(XENIFACE_SHAREDINFO_GET_TIME_OUT)) ||
        (ControlCode == IOCTL_XENIFACE_SHAREDINFO_GET_HOST_TIME &&
         OutLen != sizeof(XENIFACE_SHAREDINFO_GET_HOST_TIME_OUT)))
        goto fail2;

    XENBUS_SHARED_INFO(GetTime,
                       &Fdo->SharedInfoInterface,
                       &Time,
                       &Offset,
                       &Flags);

    switch (ControlCode) {
    case IOCTL_XENIFACE_SHAREDINFO_GET_TIME: {
        PXENIFACE_SHAREDINFO_GET_TIME_OUT       Out;

        Out = (PXENIFACE_SHAREDINFO_GET_TIME_OUT)Buffer;
        Out->Time.dwHighDateTime = Time.HighPart;
        Out->Time.dwLowDateTime = Time.LowPart;
        Out->Local = (Flags & XENBUS_SHARED_INFO_TIME_IS_LOCAL) ? TRUE : FALSE;
        Irp->IoStatus.Information =
            (ULONG_PTR)sizeof(XENIFACE_SHAREDINFO_GET_TIME_OUT);
        break;
    }
    case IOCTL_XENIFACE_SHAREDINFO_GET_HOST_TIME: {
        PXENIFACE_SHAREDINFO_GET_TIME_OUT   Out2;

        Out2 = (PXENIFACE_SHAREDINFO_GET_TIME_OUT)Buffer;

        status = STATUS_NOT_SUPPORTED;
        if (!(Flags & XENBUS_SHARED_INFO_TIME_OFFSET_IS_VALID))
            goto fail3;

        Time.QuadPart -= Offset.QuadPart;
        Out2->Time.dwHighDateTime = Time.HighPart;
        Out2->Time.dwLowDateTime = Time.LowPart;

        Irp->IoStatus.Information =
            (ULONG_PTR)sizeof(XENIFACE_SHAREDINFO_GET_HOST_TIME_OUT);
        break;
    }
    }

    return STATUS_SUCCESS;

fail3:
fail2:
fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}
