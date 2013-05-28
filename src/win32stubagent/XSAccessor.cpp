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
//#include "xs_private.h"
#include "WMIAccessor.h"

static __declspec(thread) void *WmiSessionHandle = NULL;

static LONG volatile threadcount = 0;
static __declspec(thread) LONG localthreadcount = 0;

static int64_t update_cnt;
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
        OutputDebugString("XsFree() invoked on bad pointer");
        DebugBreak();
    }
    free(orig_buf);
}

void GetXenTime(FILETIME *now)
{
    *now = WmiGetXenTime(wmi);
}

int ListenSuspend(HANDLE event)
{
    if (!WmiUnsuspendedEventWatch(wmi, event))
        return -1;
    else
        return 0;
}

void InitXSAccessor()
{
    DBGPRINT(("XSAccessor"));
    if (WmiSessionHandle == NULL) {
        if (localthreadcount == 0) {
            localthreadcount = InterlockedIncrement(&threadcount);
        }
        char wminame[12];
        _snprintf(wminame, 12, "XS%x", localthreadcount);
        WmiSessionStart(wmi, &WmiSessionHandle, wminame);
    }
    if (WmiSessionHandle == NULL)
        exit(1);
}

void XsLog(const char *fmt, ...)
{
    va_list args;
    if (!WmiSessionHandle) {
        InitXSAccessor();
    }

    va_start(args, fmt);
    WmiSessionLog(wmi, &WmiSessionHandle, fmt, args);
    va_end(args);
}


void ShutdownXSAccessor(void)
{
    WmiSessionEnd(wmi, WmiSessionHandle);

}

int XenstorePrintf(const char *path, const char *fmt, ...)
{
    va_list l;
    char buf[4096];
    int ret;
    int cnt;

    va_start(l, fmt);
    cnt = _vsnprintf(buf, sizeof(buf), fmt, l);
    va_end(l);
    if (cnt < 0) {
        DBGPRINT (("Cannot format data for XenstorePrintf!"));
        return -1;
    }

    /* Now have the thing we're trying to write. */
    return WmiSessionSetEntry(wmi, &WmiSessionHandle, path, buf);
}

int XenstoreWrite(const char *path, const void *data, size_t len)
{
    return WmiSessionSetEntry(wmi, &WmiSessionHandle, path, (const char *)data, len);
}

void XenstoreKickXapi()
{
    /* Old protocol */
    WmiSessionSetEntry(wmi, &WmiSessionHandle, "data/updated", "1");
    /* New protocol */
    XenstorePrintf("data/update_cnt", "%I64d", update_cnt);

    update_cnt++;
}

void XenstoreDoDump(VMData *data)
{
    XenstorePrintf("data/meminfo_free", "%I64d", data->meminfo_free);
    XenstorePrintf("data/meminfo_total", "%I64d", data->meminfo_total);
}

int XenstoreDoNicDump(
    uint32_t num_vif,
    VIFData *vif
    )
{
    DWORD hStatus;
    unsigned int i;
    int ret = 0;
    char path[MAX_CHAR_LEN] = "";
    const char* domainVifPath = "data/vif";
    unsigned int entry;     
    unsigned int numEntries;
    char** vifEntries = NULL;
    char vifNode[MAX_XENBUS_PATH];

    //
    // Do any cleanup first outside of a transaction since failures are allowed
    // and in some cases expected.
    //
    // Remove all of the old vif entries in case the nics have been
    // disabled.  Otherwise they will have old stale data in xenstore.
    //
    if (XenstoreList(domainVifPath, &vifEntries, &numEntries) >= 0) {
        for (entry = 0; entry < numEntries; entry++) {
            _snprintf(path, MAX_CHAR_LEN, "%s", vifEntries[entry]);
            WmiSessionRemoveEntry(wmi, &WmiSessionHandle, path);
            _snprintf(path, MAX_CHAR_LEN, "attr/eth%s", vifEntries[entry]+9);
            WmiSessionRemoveEntry(wmi, &WmiSessionHandle, path);
            XsFree(vifEntries[entry]);
        }
        XsFree(vifEntries);
    }
    do 
    {
        hStatus = ERROR_SUCCESS;
        WmiSessionTransactionStart(wmi, &WmiSessionHandle );
        ret |= XenstorePrintf("data/num_vif", "%d", num_vif);

        for( i = 0; i < num_vif; i++ ){
            if (vif[i].ethnum != -1) {
                _snprintf(path, MAX_CHAR_LEN, "data/vif/%d/name" , vif[i].ethnum);
                path[MAX_CHAR_LEN-1] = 0;
                ret |= XenstorePrintf(path, "%s", vif[i].name);


                //
                // IP address is dumped to /attr/eth[x]/ip
                //
                _snprintf (path, MAX_CHAR_LEN, "attr/eth%d/ip", vif[i].ethnum);
                path[MAX_CHAR_LEN-1] = 0;
                ret |= XenstorePrintf (path, "%s", vif[i].ip);

            }
        }
        if(!WmiSessionTransactionCommit(wmi, &WmiSessionHandle))
        {
            hStatus = GetLastError ();
            if (hStatus != ERROR_RETRY)
            {
                return -1;
            }
        }

    } while (hStatus == ERROR_RETRY);
	return ret;
}

int
XenstoreList(const char *path, char ***entries, unsigned *numEntries)
{
    *entries = WmiSessionGetChildren(wmi, &WmiSessionHandle, path, numEntries);
    if (*entries) {
        return 0;
    }
    else {
        return -1;
    }
}

int
XenstoreRemove(const char *path)
{
    if (WmiSessionRemoveEntry(wmi, &WmiSessionHandle, path))
        return -1;
    else
        return 0;
}

ssize_t
XenstoreRead(const char* path, char** value)
{
    size_t len;
    *value =WmiSessionGetEntry(wmi, &WmiSessionHandle, path, &len);
    if (*value)
        return len;
    else
        return -1;
}

void *
XenstoreWatch(const char *path, HANDLE event)
{
 
    return WmiSessionWatch(wmi, &WmiSessionHandle, path, event);
}

void
XenstoreUnwatch(void *watch)
{
    return WmiSessionUnwatch(wmi, &WmiSessionHandle, watch);
}

void 
XenstoreFree(void *tofree)
{
    return free(tofree);
}

