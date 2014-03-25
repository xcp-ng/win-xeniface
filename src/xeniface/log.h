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

#ifndef _XENIFACE_LOG_H
#define _XENIFACE_LOG_H

#include <ntddk.h>
#include <stdarg.h>

#define     ERROR    DPFLTR_ERROR_LEVEL
#define     WARNING  DPFLTR_WARNING_LEVEL
#define     TRACE    DPFLTR_TRACE_LEVEL
#define     INFO     DPFLTR_INFO_LEVEL

#pragma warning(disable:4127)   // conditional expression is constant

#define __MODULE__ "XENIFACE"

static __inline VOID
__Error(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_ERROR_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Error(...)  \
        __Error(__MODULE__ "|" __FUNCTION__ ": ", __VA_ARGS__)

static __inline VOID
__Warning(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_WARNING_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Warning(...)  \
        __Warning(__MODULE__ "|" __FUNCTION__ ": ", __VA_ARGS__)

#if DBG
static __inline VOID
__Trace(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_TRACE_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Trace(...)  \
        __Trace(__MODULE__ "|" __FUNCTION__ ": ", __VA_ARGS__)
#else   // DBG
#define Trace(...)  (VOID)(__VA_ARGS__)
#endif  // DBG

static __inline VOID
__Info(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_INFO_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Info(...)  \
        __Info(__MODULE__ "|"  __FUNCTION__ ": ", __VA_ARGS__)


#define XenIfaceDebugPrint(LEVEL, ...) \
	__XenIfaceDebugPrint(__MODULE__ "|" __FUNCTION__ ": ",LEVEL, __VA_ARGS__)

static __inline VOID
__XenIfaceDebugPrint    (
	__in const CHAR *Prefix,
    __in ULONG   DebugPrintLevel,
    __in PCCHAR  DebugMessage,
    ...
    )

{
    va_list    list;

#if !DBG
    if (DebugPrintLevel == TRACE)
        return;
#endif

    va_start(list, DebugMessage);

    if (DebugMessage)
    {
        vDbgPrintExWithPrefix(Prefix, DPFLTR_IHVDRIVER_ID, DebugPrintLevel, DebugMessage, list);

    }
    va_end(list);

    return;
}


#endif  // _XENIFACE_LOG_H
