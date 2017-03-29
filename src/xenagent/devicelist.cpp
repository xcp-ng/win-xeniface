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
#include <string>
#include <setupapi.h>
#pragma comment (lib , "setupapi.lib" )

#include "devicelist.h"

// deal with SetupApi and RegisterDeviceNotification using different string types
static std::wstring Convert(const char* str)
{
    std::wstring wstr;
    wstr.reserve(strlen(str) + 1);
    MultiByteToWideChar(CP_ACP, 0, str, -1, (LPWSTR)wstr.data(), (int)wstr.capacity());
    return wstr;
}

static std::wstring Convert(const wchar_t* wstr)
{
    return std::wstring(wstr);
}

CDevice::CDevice(const wchar_t* path) :
    m_handle(INVALID_HANDLE_VALUE), m_path(path), m_notify(NULL)
{
}

/*virtual*/ CDevice::~CDevice()
{
    Close();
}

const wchar_t* CDevice::Path() const
{
    return m_path.c_str();
}

HANDLE CDevice::Open(HANDLE svc)
{
    Close();

    m_handle = CreateFileW(m_path.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_EXISTING,
                           0,
                           NULL);
    if (m_handle == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    DEV_BROADCAST_HANDLE devhdl = { 0 };
    devhdl.dbch_size = sizeof(devhdl);
    devhdl.dbch_devicetype = DBT_DEVTYP_HANDLE;
    devhdl.dbch_handle = m_handle;

    m_notify = RegisterDeviceNotification(svc, &devhdl, DEVICE_NOTIFY_SERVICE_HANDLE);
    if (m_notify == NULL) {
        Close();
        return INVALID_HANDLE_VALUE;
    }

    return m_handle;
}

void CDevice::Close()
{
    if (m_handle == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(m_handle);
    m_handle = INVALID_HANDLE_VALUE;
}

bool CDevice::Write(void *buf, DWORD bufsz, DWORD *bytes /* = NULL*/)
{
    if (m_handle == INVALID_HANDLE_VALUE)
        return false;

    DWORD _bytes;
    if (!WriteFile(m_handle,
                   buf,
                   bufsz,
                   (bytes == NULL) ? &_bytes : bytes,
                   NULL))
        return false;

    return true;
}

bool CDevice::Ioctl(DWORD ioctl, void* in, DWORD insz, void* out, DWORD outsz, DWORD* bytes /*= NULL*/)
{
    if (m_handle == INVALID_HANDLE_VALUE)
        return false;

    DWORD _bytes;
    if (!DeviceIoControl(m_handle,
                         ioctl,
                         in,
                         insz,
                         out,
                         outsz,
                         (bytes == NULL) ? &_bytes : bytes,
                         NULL))
        return false;

    return true;
}

CDeviceList::CDeviceList(const GUID& itf) :
    m_guid(itf), m_notify(NULL), m_handle(NULL), m_impl(NULL)
{
}

CDeviceList::~CDeviceList()
{
    Stop();
}

#pragma warning(push)
#pragma warning(disable:6102) // Using value from failed function call

bool CDeviceList::Start(HANDLE handle, IDeviceCreator* impl)
{
    Stop();

    m_handle = handle;
    m_impl = impl;

    DEV_BROADCAST_DEVICEINTERFACE dev = { 0 };
    dev.dbcc_size = sizeof(dev);
    dev.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    dev.dbcc_classguid = m_guid;

    m_notify = RegisterDeviceNotificationA(handle, &dev, DEVICE_NOTIFY_SERVICE_HANDLE);
    if (m_notify == NULL)
        return false;

    HDEVINFO                            info;
    SP_DEVICE_INTERFACE_DATA            itf;
    PSP_DEVICE_INTERFACE_DETAIL_DATA    detail;
    ULONG                               idx;
    ULONG                               len;

    info = SetupDiGetClassDevs(&m_guid,
                               NULL,
                               NULL,
                               DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (info == INVALID_HANDLE_VALUE)
        return true; // non fatal, just missing already present device(s)

    itf.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    for (idx = 0;
        SetupDiEnumDeviceInterfaces(info, NULL, &m_guid, idx, &itf);
        ++idx) {
        SetupDiGetDeviceInterfaceDetail(info,
                                        &itf,
                                        NULL,
                                        0,
                                        &len,
                                        NULL);
        detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)new BYTE[len];
        if (detail == NULL)
            continue;
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if (SetupDiGetDeviceInterfaceDetail(info,
                                            &itf,
                                            detail,
                                            len,
                                            NULL,
                                            NULL)) {
            OnDeviceAdded(Convert((const char*)detail->DevicePath));
        }
        delete [] detail;
        itf.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    }
    SetupDiDestroyDeviceInfoList(info);
    return true;
}

#pragma warning(pop)

void CDeviceList::Stop()
{
    if (m_notify != NULL)
        UnregisterDeviceNotification(m_notify);
    m_notify = NULL;

    for (DeviceMap::iterator it = m_devs.begin();
            it != m_devs.end();
            ++it) {
        delete it->second;
    }
    m_devs.clear();
}

void CDeviceList::OnDeviceEvent(DWORD evt, LPVOID data)
{
    PDEV_BROADCAST_HDR              hdr;
    PDEV_BROADCAST_DEVICEINTERFACE  itf;
    PDEV_BROADCAST_HANDLE           hdl;

    hdr = (PDEV_BROADCAST_HDR)data;
    switch (evt) {
    case DBT_DEVICEARRIVAL:
        if (hdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
            itf = (PDEV_BROADCAST_DEVICEINTERFACE)hdr;
            if (itf->dbcc_classguid == m_guid)
                OnDeviceAdded(Convert((const wchar_t*)itf->dbcc_name));
        }
        break;

    case DBT_DEVICEQUERYREMOVE:
        if (hdr->dbch_devicetype == DBT_DEVTYP_HANDLE) {
            hdl = (PDEV_BROADCAST_HANDLE)hdr;
            OnDeviceQueryRemove(hdl->dbch_handle);
        }
        break;

    case DBT_DEVICEREMOVEPENDING:
        if (hdr->dbch_devicetype == DBT_DEVTYP_HANDLE) {
            hdl = (PDEV_BROADCAST_HANDLE)hdr;
            UnregisterDeviceNotification(hdl->dbch_hdevnotify);
            OnDeviceRemoved(hdl->dbch_handle);
        }
        break;

    default:
        break;
    }
}

void CDeviceList::OnPowerEvent(DWORD evt, LPVOID data)
{
    UNREFERENCED_PARAMETER(data);

    switch (evt) {
    case PBT_APMRESUMESUSPEND:
    for (DeviceMap::iterator it = m_devs.begin();
         it != m_devs.end();
         ++it)
        m_impl->OnDeviceResume(it->second);
    break;

    case PBT_APMSUSPEND:
    for (DeviceMap::iterator it = m_devs.begin();
         it != m_devs.end();
         ++it)
        m_impl->OnDeviceSuspend(it->second);
    break;

    default:
        break;
    }
}

CDevice* CDeviceList::GetFirstDevice()
{
    DeviceMap::iterator it = m_devs.begin();
    if (it == m_devs.end())
        return NULL;
    return it->second;
}

void CDeviceList::OnDeviceAdded(const std::wstring& path)
{
    CDevice* dev;
    if (m_impl == NULL)
        dev = new CDevice(path.c_str());
    else
        dev = m_impl->Create(path.c_str());
    if (dev == NULL)
        return; // create failed

    HANDLE handle = dev->Open(m_handle);
    if (handle == INVALID_HANDLE_VALUE) {
        delete dev;
        return; // open failed
    }

    DeviceMap::iterator it = m_devs.find(handle);
    if (it != m_devs.end()) {
        delete dev;
        return;
    }

    m_devs[handle] = dev;
    if (m_impl)
        m_impl->OnDeviceAdded(dev);
}

void CDeviceList::OnDeviceQueryRemove(HANDLE handle)
{
    DeviceMap::iterator it = m_devs.find(handle);
    if (it == m_devs.end())
        return; // spurious event?

    CDevice* dev = it->second;
    if (m_impl)
        m_impl->OnDeviceRemoved(dev);
    dev->Close();
}

void CDeviceList::OnDeviceRemoved(HANDLE handle)
{
    DeviceMap::iterator it = m_devs.find(handle);
    if (it == m_devs.end())
        return; // spurious event?

    CDevice* dev = it->second;
    delete dev;
    m_devs.erase(it);
}
