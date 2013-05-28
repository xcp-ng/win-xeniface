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
#include "NicInfo.h"
#include "XSAccessor.h"
#include <winsock2.h>
#include <Iphlpapi.h>

NicInfo::NicInfo() : netif_data(NULL), nr_netifs_found(0)
{
    NicChangeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!NicChangeEvent) {
        XsLog("Failed to create NicChangeEvent");
        exit(1);
    }

    ResetEvent(NicChangeEvent);

    memset(&Overlap, 0, sizeof (Overlap));
    Overlap.hEvent = NicChangeEvent;
}

NicInfo::~NicInfo()
{
    //CancelIPChangeNotify(&Overlap); <--- Function does not exist in 2k
}

void NicInfo::Prime()
{
    DWORD dwRet;
    LONG  Attempt;

    Attempt = 0;
again:
    dwRet = NotifyAddrChange(&hAddrChange, &Overlap);
    if (dwRet != NO_ERROR) {
        dwRet = GetLastError();
        if (dwRet != ERROR_IO_PENDING) {
            XsLog("NotifyAddrChange(%d) failed: 0x%08x", Attempt, dwRet);
            if (++Attempt >= 5)
                return;

            Sleep(1000); // 1s
            goto again;
        }
    }
}

void NicInfo::Refresh()
{
    GetNicInfo();
    XenstoreDoNicDump(nr_netifs_found, netif_data);
}

void NicInfo::GetNicInfo()
{
    const char* domainVifPath = "device/vif";
    unsigned int entry;     
    int i;
    unsigned int numEntries;
    char** vifEntries = NULL;
    char vifNode[MAX_XENBUS_PATH];
    PIP_ADAPTER_INFO IpAdapterInfo = NULL;
    PIP_ADAPTER_INFO currAdapterInfo;
    ULONG cbIpAdapterInfo;
    ULONG numIpAdapterInfo;
    char AdapterMac[MAX_CHAR_LEN];

    //
    // Get the list of vif #'s from xenstore
    //
	if (XenstoreList(domainVifPath, &vifEntries, &numEntries) < 0) {
		goto clean;
	}
    nr_netifs_found = 0;
    if (netif_data) {
        free(netif_data);
        netif_data = NULL;
    }
	netif_data = (VIFData *)calloc(sizeof(VIFData), numEntries);
    if (!netif_data) {
        goto clean;
    }

    //
    // Loop through xenstore and collect the vif number and the mac address
    //
    for (entry = 0; entry < numEntries; entry++) {
        netif_data[entry].ethnum = atoi(vifEntries[entry]); 
        char* macAddress;
#pragma prefast(suppress: 28719, "We know the max length of the string")
        sprintf(vifNode, "%s/mac", vifEntries[entry]);
        if (XenstoreRead(vifNode, &macAddress) != -1) {
#pragma prefast(suppress: 28719, "We know the max length of the string")
            lstrcpyn(netif_data[entry].mac, macAddress, sizeof(netif_data[entry].mac));
            XenstoreFree(macAddress);
        }
    }

    //
    // Call GetAdaptersInfo to get a list of network device information.
    // Use this to cooralate a mac address to an IP address and the nics name.
    //
    cbIpAdapterInfo = 0;
    if (GetAdaptersInfo(NULL, &cbIpAdapterInfo) != ERROR_BUFFER_OVERFLOW) {
        goto clean;
    }
    IpAdapterInfo = (PIP_ADAPTER_INFO)malloc(cbIpAdapterInfo);
    if (!IpAdapterInfo) {
        goto clean;
    }
    if (GetAdaptersInfo(IpAdapterInfo, &cbIpAdapterInfo) != NO_ERROR) {
        goto clean;
    }

    currAdapterInfo = IpAdapterInfo;
    while (currAdapterInfo) {
#pragma prefast(suppress:28719, "We know the max length of the string")
        sprintf(AdapterMac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            currAdapterInfo->Address[0], currAdapterInfo->Address[1], currAdapterInfo->Address[2],
            currAdapterInfo->Address[3], currAdapterInfo->Address[4], currAdapterInfo->Address[5]);

        for (entry = 0; entry < numEntries; entry++) {
            if (!lstrcmpi(AdapterMac, netif_data[entry].mac)) {
                //
                // Found the matching netif_data entry, so fill in the other values from
                // the IP_ADAPTER_INFO values.
                //
#pragma prefast(suppress: 28719, "We know the max length of the string")
                lstrcpyn(netif_data[entry].name, currAdapterInfo->Description, sizeof(netif_data[entry].name));
#pragma prefast(suppress: 28719, "We know the max length of the string")
                lstrcpyn(netif_data[entry].ip, currAdapterInfo->IpAddressList.IpAddress.String, sizeof(netif_data[entry].ip));
                break;
            }
        }

        currAdapterInfo = currAdapterInfo->Next;
    }

    nr_netifs_found = numEntries;
clean:
    if (vifEntries) {
        for (entry = 0; entry < numEntries; entry++)
            XenstoreFree(vifEntries[entry]);
        XenstoreFree(vifEntries);
    }
    if (IpAdapterInfo) {
        free(IpAdapterInfo);
    }
}
