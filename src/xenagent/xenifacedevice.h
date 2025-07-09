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

#ifndef __XENAGENT_XENIFACEDEVICE_H__
#define __XENAGENT_XENIFACEDEVICE_H__

#include <windows.h>
#include <string>
#include "devicelist.h"

class CXenIfaceDevice : public CDevice
{
public:
    CXenIfaceDevice(const wchar_t* path);
    virtual ~CXenIfaceDevice();

public: // store interface
    bool StoreRead(const std::string& path, std::string& value);
    bool StoreWrite(const std::string& path, const std::string& value);
    bool StoreRemove(const std::string& path);
    bool StoreAddWatch(const std::string& path, HANDLE evt, void** ctxt);
    bool StoreRemoveWatch(void* ctxt);

public: // suspend interface
    bool SuspendRegister(HANDLE evt, void** ctxt);
    bool SuspendDeregister(void* ctxt);
    bool SuspendGetCount(DWORD *count);

public: // sharedinfo interface
    bool SharedInfoGetTime(FILETIME* time, bool *local);

public: // logging
    bool Log(const std::string& msg);
};

class CXenAgent;

class CXenIfaceDeviceList : public CDeviceList
{
public:
    CXenIfaceDeviceList(CXenAgent* agent);
    virtual ~CXenIfaceDeviceList();

protected: // CDeviceList
    virtual CDevice* Create(const wchar_t* path);
    virtual void OnDeviceAdded(CDevice* dev);
    virtual void OnDeviceRemoved(CDevice* dev);
    virtual void OnDeviceSuspend(CDevice* dev);
    virtual void OnDeviceResume(CDevice* dev);

public:
    HANDLE  m_evt_shutdown;
    HANDLE  m_evt_suspend;
    HANDLE  m_evt_slate_mode;

    void Log(const char* message);
    bool CheckShutdown();
    void CheckXenTime(bool forced);
    void CheckSuspend();
    bool CheckSlateMode(std::string& mode);
    void LogIfRebootPending();

private:
    void StartShutdownWatch(CXenIfaceDevice* device);
    void StopShutdownWatch(CXenIfaceDevice* device);
    void StartSlateModeWatch(CXenIfaceDevice* device);
    void StopSlateModeWatch(CXenIfaceDevice* device);
    void AcquireShutdownPrivilege();
    void SetXenTime(CXenIfaceDevice* device, bool forced);

private:
    CXenAgent*  m_agent;
    DWORD       m_count;
    void*       m_ctxt_suspend;
    void*       m_ctxt_shutdown;
    void*       m_ctxt_slate_mode;
};

#endif
