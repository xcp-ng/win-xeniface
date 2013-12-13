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

#include <windows.h>
#include "stdafx.h"
#include "XSAccessor.h"
#include "WMIAccessor.h"

static __declspec(thread) void *WmiSessionHandle = NULL;

static LONG volatile threadcount = 0;
static __declspec(thread) LONG localthreadcount = 0;
static __declspec(thread) LONG localwmicount = 0;

static long update_cnt=0xF0000000;
#define XENSTORE_MAGIC 0x7e6ec123

void *XsAlloc(size_t size) {
    void *buf;

    buf = malloc(size + 8);
    if (!buf) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memset(buf, 0, size + 8);
    *(unsigned *)buf = XENSTORE_MAGIC;
    return (void *)((ULONG_PTR)buf + 8);
}

void XsFree(const void *buf) {
    void *orig_buf;

    if (!buf)
        return;
    orig_buf = (void *)((ULONG_PTR)buf - 8);
    if (*(unsigned *)orig_buf != XENSTORE_MAGIC) {
        OutputDebugString("XsFree() invoked on bad pointer\n");
        DebugBreak();
    }
    free(orig_buf);
}

void GetXenTime(FILETIME *now)
{
    *now = WmiGetXenTime(&wmi);
}


int ListenSuspend(HANDLE event, HANDLE errorevent)
{
    if (!WmiUnsuspendedEventWatch(&wmi, event, errorevent))
        return -1;
    else
        return 0;
}

BOOL InitXSAccessor()
{
    OutputDebugString("XSAccessor\n");
    if (wmicount != localwmicount) {
        
        if (localthreadcount == 0) {
            localthreadcount = InterlockedIncrement(&threadcount);
        }
        char wminame[12];
        _snprintf(wminame, 12, "XS%x", localthreadcount);
        if (WmiSessionStart(&wmi, &WmiSessionHandle, wminame)) {
            localwmicount = wmicount;
            return true;
        }
        OutputDebugString("XSAccessor Failed\n");
        return false;
    }
    return true;
}

void XsLog(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    WmiSessionLog(&wmi, &WmiSessionHandle, fmt, args);
    va_end(args);
}


BOOL ShutdownXSAccessor(void)
{
    if (wmi == NULL) {
        return false;
    }
    if (WmiSessionHandle == NULL) {
        return false;
    }
    return WmiSessionEnd(&wmi, WmiSessionHandle);

}

int XenstorePrintf(const char *path, const char *fmt, ...)
{
    va_list l;
    char buf[4096];
    int cnt;

    va_start(l, fmt);
    cnt = _vsnprintf(buf, sizeof(buf), fmt, l);
    va_end(l);
    if (cnt < 0) {
        DBGPRINT (("Cannot format data for XenstorePrintf!"));
        return -1;
    }
    OutputDebugString(buf);
    /* Now have the thing we're trying to write. */
    return WmiSessionSetEntry(&wmi, &WmiSessionHandle, path, buf);
}

BOOL XenstoreKickXapi()
{
    /* New protocol */
    if (XenstorePrintf("data/update_cnt", "%I64d", update_cnt)){
        XsLog("New kick failed ");
        return false;
    }
    /* Old protocol */
    if (WmiSessionSetEntry(&wmi, &WmiSessionHandle, "data/updated", "1")){
        XsLog("Old kick failed");
        return false;
    }
    update_cnt++;
    return true;
}


int
XenstoreRemove(const char *path)
{
    if (wmi == NULL)
        return -1;

    if (WmiSessionHandle == NULL)
        return -1;

    if (WmiSessionRemoveEntry(&wmi, &WmiSessionHandle, path))
        return -1;
    else
        return 0;
}

ssize_t
XenstoreRead(const char* path, char** value)
{
    size_t len;
    *value =WmiSessionGetEntry(&wmi, &WmiSessionHandle, path, &len);
    if (*value)
        return (ssize_t)len;
    else
        return -1;
}

void *
XenstoreWatch(const char *path, HANDLE event, HANDLE errorevent)
{
 
    if (wmi == NULL) {
        OutputDebugString("WMI is null\n");
        return NULL;
    }
    if (WmiSessionHandle == NULL) {
        OutputDebugString("Session is null\n");
        return NULL;
    }
    return WmiSessionWatch(&wmi, &WmiSessionHandle, path, event, errorevent);
}

BOOL
XenstoreUnwatch(void *watch)
{
    return WmiSessionUnwatch(&wmi, &WmiSessionHandle, watch);
}

void 
XenstoreFree(void *tofree)
{
    return free(tofree);
}

