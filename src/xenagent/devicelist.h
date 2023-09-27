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

#ifndef __XENAGENT_DEVICELIST_H__
#define __XENAGENT_DEVICELIST_H__

#include <windows.h>
#include <dbt.h>
#include <vector>
#include <string>

class CCritSec
{
public:
    CCritSec(LPCRITICAL_SECTION crit);
    ~CCritSec();
private:
    LPCRITICAL_SECTION m_crit;
};

class CDevice
{
public:
    CDevice(const wchar_t* path);
    virtual ~CDevice();

    const wchar_t* Path() const;
    HDEVNOTIFY Notify() const;

    bool Open();
    void Close();
    bool Register(HANDLE svc);
    void Unregister();

protected:
    bool Write(void *buf, DWORD bufsz, DWORD *bytes = NULL);
    bool Ioctl(DWORD ioctl, void* in, DWORD insz, void* out, DWORD outsz, DWORD* bytes = NULL);

private:
    std::wstring    m_path;
    HANDLE          m_handle;
    HDEVNOTIFY      m_notify;
};

class CDeviceList
{
protected:
    CDeviceList(const GUID& itf);

    virtual CDevice* Create(const wchar_t* path) = 0;
    virtual void OnDeviceAdded(CDevice* dev)     = 0;
    virtual void OnDeviceRemoved(CDevice* dev)   = 0;
    virtual void OnDeviceSuspend(CDevice* dev)   = 0;
    virtual void OnDeviceResume(CDevice* dev)    = 0;

    CRITICAL_SECTION    m_crit;

public:
    virtual ~CDeviceList();

    CDevice* GetFirstDevice();

    bool RegisterForDeviceChange(HANDLE svc);
    void UnregisterForDeviceChange();
    void EnumerateDevices();
    void CleanupDeviceList();

    void OnDeviceEvent(DWORD evt, LPVOID data);
    void OnPowerEvent(DWORD evt, LPVOID data);

private:
    void DeviceArrival(const std::wstring& path);
    void DeviceRemoved(HDEVNOTIFY nfy);
    void DeviceRemovePending(HDEVNOTIFY nfy);
    void DeviceRemoveFailed(HDEVNOTIFY nfy);

    typedef std::vector< CDevice* > DeviceMap;

    GUID                m_guid;
    DeviceMap           m_devs;
    HDEVNOTIFY          m_notify;
    HANDLE              m_handle;
};

#endif
