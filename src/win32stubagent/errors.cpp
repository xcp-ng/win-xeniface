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

/* Black-box data recorder.  This records stuff which is happening
   while the agent runs, and tries to push it out to dom0 syslog if we
   crash. */
#include "stdafx.h"
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "XService.h"
#include "XSAccessor.h"


#define RING_SIZE 8192

struct message_ring {
    HANDLE handle;
    unsigned prod_idx;
    unsigned cons_idx;
    unsigned char payload[RING_SIZE];
};

static __declspec(thread) struct message_ring message_ring;

static char *
Xsvasprintf(const char *fmt, va_list args)
{
    char *work;
    int work_size;
    int r;

    work_size = 32;
    while (1) {
        work = (char *)malloc(work_size);
        if (!work)
            return work;
        r = _vsnprintf(work, work_size, fmt, args);
        if (r == 0) {
            free(work);
            return NULL;
        }
        if (r != -1 && r < work_size) {
            return work;
        }
        free(work);
        work_size *= 2;
    }
}

static char *
Xsasprintf(const char *fmt, ...)
{
    va_list args;
    char *res;

    va_start(args, fmt);
    res = Xsvasprintf(fmt, args);
    va_end(args);
    return res;
}

void
XsLogMsg(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    XsLog(fmt, args);
    va_end(args);
}


