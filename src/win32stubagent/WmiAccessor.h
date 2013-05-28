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

#ifndef _WMIACCESSOR_H
#define _WMIACCESSOR_H

#include <Wbemidl.h>
#include <list>
#include <vector>
#include <map>
#include <string>

#include "vm_stats.h"
#include "XSAccessor.h"

using namespace std;

typedef unsigned __int64 uint64_t;

struct WMIAccessor;

extern struct WMIAccessor *wmi;

void ConnectToWMI(void);
void ReleaseWMIAccessor(struct WMIAccessor *);

void GetWMIData(WMIAccessor *wmi, VMData& data);
void DumpOSData(WMIAccessor *wmi);

VOID AddHotFixInfoToStore(WMIAccessor* wmi);
void UpdateProcessListInStore(WMIAccessor *wmi);

int WmiSessionSetEntry(WMIAccessor* wmi,  void **sessionhandle, 
              const char*path, const char * value);

int WmiSessionSetEntry(WMIAccessor* wmi,  void **sessionhandle, 
              const char*path, const char * value, size_t len);
char* WmiSessionGetEntry(WMIAccessor* wmi, void **sessionhandle,
              const char * path, size_t* len) ;

void *WmiSessionWatch(WMIAccessor* wmi,  void **sessionhandle, 
                      const char *path, HANDLE event);
void WmiSessionUnwatch(WMIAccessor* wmi,  void **sessionhandle,
                         void *watchhandle);

int WmiSessionRemoveEntry(WMIAccessor* wmi,  void **sessionhandle, 
              const char*path);

char **WmiSessionGetChildren(WMIAccessor* wmi, void **sessionhandle,
              const char * path, unsigned *numentries);


void *WmiUnsuspendedEventWatch(WMIAccessor *wmi, HANDLE event);

int WmiSessionTransactionAbort(WMIAccessor* wmi,  void **sessionhandle); 
int WmiSessionTransactionCommit(WMIAccessor* wmi,  void **sessionhandle); 
int WmiSessionTransactionStart(WMIAccessor* wmi,  void **sessionhandle); 
void WmiSessionStart(WMIAccessor* wmi,  void **sessionhandle, const char *sessionname);
void WmiSessionEnd(WMIAccessor* wmi,  void *sessionhandle);
FILETIME WmiGetXenTime(WMIAccessor *wmi);
void WmiSessionLog(WMIAccessor* wmi,  void **sessionhandle,const char *fmt, va_list args);
#endif
