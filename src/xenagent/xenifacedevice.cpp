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

#define INITGUID
#include <windows.h>
#include <winioctl.h>
#include <powrprof.h>

#include "service.h"
#include "xenifacedevice.h"
#include "devicelist.h"
#include "xeniface_ioctls.h"
#include "messages.h"

CXenIfaceDevice::CXenIfaceDevice(const wchar_t* path) : CDevice(path)
{}

/*virtual*/ CXenIfaceDevice::~CXenIfaceDevice()
{}

// store interface
bool CXenIfaceDevice::StoreRead(const std::string& path, std::string& value)
{
    DWORD   bytes(0);
    char*   buffer;
    bool    result;

    Ioctl(IOCTL_XENIFACE_STORE_READ,
          (void*)path.c_str(), (DWORD)path.length() + 1,
          NULL, 0,
          &bytes);

    buffer = new char[(size_t)bytes + 1];
    if (buffer == NULL)
        return false;

    result = Ioctl(IOCTL_XENIFACE_STORE_READ,
                   (void*)path.c_str(), (DWORD)path.length() + 1,
                   buffer, bytes);

    buffer[bytes] = 0;
    if (result)
        value = buffer;

    delete [] buffer;
    return result;
}

bool CXenIfaceDevice::StoreWrite(const std::string& path, const std::string& value)
{
    bool   result;
    size_t length = path.length() + 1 + value.length() + 1 + 1;
    char*  buffer = new char[length];
    if (buffer == NULL)
        return false;

    memcpy(buffer, path.c_str(), path.length());
    buffer[path.length()] = 0;

    memcpy(buffer + path.length() + 1, value.c_str(), value.length());
    buffer[path.length() + 1 + value.length()] = 0;
    buffer[length - 1] = 0;

    result = Ioctl(IOCTL_XENIFACE_STORE_WRITE, buffer, (DWORD)length, NULL, 0);
    delete [] buffer;
    return result;
}

bool CXenIfaceDevice::StoreRemove(const std::string& path)
{
    return Ioctl(IOCTL_XENIFACE_STORE_REMOVE,
                 (void*)path.c_str(), (DWORD)path.length() + 1,
                 NULL, 0);
}

bool CXenIfaceDevice::StoreAddWatch(const std::string& path, HANDLE evt, void** ctxt)
{
    XENIFACE_STORE_ADD_WATCH_IN  in  = { (PCHAR)path.c_str(), (DWORD)path.length() + 1, evt };
    XENIFACE_STORE_ADD_WATCH_OUT out = { };
    if (!Ioctl(IOCTL_XENIFACE_STORE_ADD_WATCH,
               &in, (DWORD)sizeof(in),
               &out, (DWORD)sizeof(out)))
        return false;
    *ctxt = out.Context;
    return true;
}

bool CXenIfaceDevice::StoreRemoveWatch(void* ctxt)
{
    XENIFACE_STORE_REMOVE_WATCH_IN in = { ctxt };
    return Ioctl(IOCTL_XENIFACE_STORE_REMOVE_WATCH,
                 &in, (DWORD)sizeof(in),
                 NULL, 0);
}

// suspend interface
bool CXenIfaceDevice::SuspendRegister(HANDLE evt, void** ctxt)
{
    XENIFACE_SUSPEND_REGISTER_IN  in  = { evt };
    XENIFACE_SUSPEND_REGISTER_OUT out = { };
    if (!Ioctl(IOCTL_XENIFACE_SUSPEND_REGISTER,
               &in, (DWORD)sizeof(in),
               &out, (DWORD)sizeof(out)))
        return false;
    *ctxt = out.Context;
    return true;
}

bool CXenIfaceDevice::SuspendDeregister(void* ctxt)
{
    XENIFACE_SUSPEND_REGISTER_OUT in = { ctxt };
    return Ioctl(IOCTL_XENIFACE_SUSPEND_DEREGISTER,
                 &in, (DWORD)sizeof(in),
                 NULL, 0);
}

bool CXenIfaceDevice::SuspendGetCount(DWORD *count)
{
    DWORD out;
    if (!Ioctl(IOCTL_XENIFACE_SUSPEND_GET_COUNT,
                NULL, 0,
                &out, (DWORD)sizeof(out)))
        return false;
    *count = out;
    return true;
}

// sharedinfo interface
bool CXenIfaceDevice::SharedInfoGetTime(FILETIME* time, bool* local)
{
    XENIFACE_SHAREDINFO_GET_TIME_OUT out = { };
    if (!Ioctl(IOCTL_XENIFACE_SHAREDINFO_GET_TIME,
               NULL, 0,
               &out, sizeof(out)))
        return false;
    *time = out.Time;
    *local = out.Local;
    return true;
}

// logging
bool CXenIfaceDevice::Log(const std::string& msg)
{
    return Ioctl(IOCTL_XENIFACE_LOG,
                 (void*)msg.c_str(), (DWORD)msg.length() + 1,
                 NULL, 0);
}

CXenIfaceDeviceList::CXenIfaceDeviceList(CXenAgent* agent) : CDeviceList(GUID_INTERFACE_XENIFACE),
    m_agent(agent),
    m_ctxt_suspend(NULL),
    m_ctxt_shutdown(NULL),
    m_ctxt_slate_mode(NULL)
{
    m_evt_shutdown = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_evt_suspend = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_evt_slate_mode = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_count = 0;
}

/*virtual*/ CXenIfaceDeviceList::~CXenIfaceDeviceList()
{
    CloseHandle(m_evt_slate_mode);
    CloseHandle(m_evt_suspend);
    CloseHandle(m_evt_shutdown);
}

/*virtual*/ CDevice* CXenIfaceDeviceList::Create(const wchar_t* path)
{
    return new CXenIfaceDevice(path);
}

/*virtual*/ void CXenIfaceDeviceList::OnDeviceAdded(CDevice* dev)
{
    CCritSec crit(&m_crit);

    if (GetFirstDevice() != NULL)
        return;

    CXenIfaceDevice* device = (CXenIfaceDevice*)dev;

    device->SuspendRegister(m_evt_suspend, &m_ctxt_suspend);
    StartShutdownWatch(device);

    if (m_agent->ConvDevicePresent())
        StartSlateModeWatch(device);

    SetXenTime(device);
}

/*virtual*/ void CXenIfaceDeviceList::OnDeviceRemoved(CDevice* dev)
{
    CCritSec crit(&m_crit);
    CXenIfaceDevice* device = (CXenIfaceDevice*)dev;

    if (dev != GetFirstDevice())
        return;

    if (m_ctxt_suspend)
        device->SuspendDeregister(m_ctxt_suspend);
    m_ctxt_suspend = NULL;

    if (m_agent->ConvDevicePresent())
        StopSlateModeWatch(device);

    StopShutdownWatch(device);
}

/*virtual*/ void CXenIfaceDeviceList::OnDeviceSuspend(CDevice* dev)
{
    CCritSec crit(&m_crit);
    CXenIfaceDevice* device = (CXenIfaceDevice*)dev;

    if (dev != GetFirstDevice())
        return;

    if (m_agent->ConvDevicePresent())
        StopSlateModeWatch(device);

    StopShutdownWatch(device);
}

/*virtual*/ void CXenIfaceDeviceList::OnDeviceResume(CDevice* dev)
{
    CCritSec crit(&m_crit);
    CXenIfaceDevice* device = (CXenIfaceDevice*)dev;

    if (dev != GetFirstDevice())
        return;

    StartShutdownWatch(device);

    if (m_agent->ConvDevicePresent())
        StartSlateModeWatch(device);
}

void CXenIfaceDeviceList::Log(const char* message)
{
    // if possible, send to xeniface to forward to logs
    if (TryEnterCriticalSection(&m_crit)) {
        CXenIfaceDevice* device = (CXenIfaceDevice*)GetFirstDevice();
        if (device != NULL)
            device->Log(message);
        LeaveCriticalSection(&m_crit);
    }
}

bool CXenIfaceDeviceList::CheckShutdown()
{
    CCritSec crit(&m_crit);
    CXenIfaceDevice* device = (CXenIfaceDevice*)GetFirstDevice();

    if (device == NULL)
        return false;

    std::string type;
    if (!device->StoreRead("control/shutdown", type))
        return false;

    if (type != "")
        CXenAgent::Log("Shutdown(%ws) = '%s'\n", device->Path(), type.c_str());

    if (type == "poweroff") {
        device->StoreWrite("control/shutdown", "");
        m_agent->EventLog(EVENT_XENUSER_POWEROFF);
        LogIfRebootPending();

        AcquireShutdownPrivilege();
#pragma warning(suppress:28159) /* Consider using a design alternative... Rearchitect to avoid Reboot */
        if (!InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, FALSE,
                                      SHTDN_REASON_MAJOR_OTHER |
                                      SHTDN_REASON_MINOR_ENVIRONMENT |
                                      SHTDN_REASON_FLAG_PLANNED)) {
            CXenAgent::Log("InitiateSystemShutdownEx failed %08x\n", GetLastError());
        }
        return true;
    } else if (type == "reboot") {
        device->StoreWrite("control/shutdown", "");
        m_agent->EventLog(EVENT_XENUSER_REBOOT);
        LogIfRebootPending();

        AcquireShutdownPrivilege();
#pragma warning(suppress:28159) /* Consider using a design alternative... Rearchitect to avoid Reboot */
        if (!InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, TRUE,
                                      SHTDN_REASON_MAJOR_OTHER |
                                      SHTDN_REASON_MINOR_ENVIRONMENT |
                                      SHTDN_REASON_FLAG_PLANNED)) {
            CXenAgent::Log("InitiateSystemShutdownEx failed %08x\n", GetLastError());
        }
        return true;
    } else if (type == "s4") {
        device->StoreWrite("control/shutdown", "");
        m_agent->EventLog(EVENT_XENUSER_S4);

        AcquireShutdownPrivilege();
        if (!SetSystemPowerState(FALSE, FALSE)) {
            CXenAgent::Log("SetSystemPowerState failed %08x\n", GetLastError());
        }
        return false;
    } else if (type == "s3") {
        device->StoreWrite("control/shutdown", "");
        m_agent->EventLog(EVENT_XENUSER_S3);

        AcquireShutdownPrivilege();
        if (!SetSuspendState(FALSE, TRUE, FALSE)) {
            CXenAgent::Log("SetSuspendState failed %08x\n", GetLastError());
        }
        return false;
    }

    return false;
}

void CXenIfaceDeviceList::CheckXenTime()
{
    CCritSec crit(&m_crit);
    CXenIfaceDevice* device = (CXenIfaceDevice*)GetFirstDevice();

    if (device == NULL)
        return;

    SetXenTime(device);
}

void CXenIfaceDeviceList::CheckSuspend()
{
    CCritSec crit(&m_crit);
    CXenIfaceDevice* device = (CXenIfaceDevice*)GetFirstDevice();

    if (device == NULL)
        return;

    DWORD count = 0;

    if (!device->SuspendGetCount(&count))
        return;

    if (m_count == count)
        return;

    CXenAgent::Log("Suspend(%ws)\n", device->Path());

    m_agent->EventLog(EVENT_XENUSER_UNSUSPENDED);

    // recreate watches, as suspending deactivated the watch
    if (m_agent->ConvDevicePresent())
        StopSlateModeWatch(device);

    StopShutdownWatch(device);

    StartShutdownWatch(device);

    if (m_agent->ConvDevicePresent())
        StartSlateModeWatch(device);

    m_count = count;
}

bool CXenIfaceDeviceList::CheckSlateMode(std::string& mode)
{
    CCritSec crit(&m_crit);
    CXenIfaceDevice* device = (CXenIfaceDevice*)GetFirstDevice();

    if (device == NULL)
        return false;

    if (!device->StoreRead("control/laptop-slate-mode", mode))
        return false;

    if (mode != "")
        device->StoreWrite("control/laptop-slate-mode", "");

    return true;
}

void CXenIfaceDeviceList::LogIfRebootPending()
{
    HKEY Key;
    LONG lResult;

    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
                           0,
                           KEY_READ,
                           &Key);
    if (lResult != ERROR_SUCCESS)
        return; // key doesnt exist, dont log anything

    RegCloseKey(Key);

    CXenAgent::Log("RebootRequired detected\n");
}

void CXenIfaceDeviceList::StartShutdownWatch(CXenIfaceDevice* device)
{
    if (m_ctxt_shutdown)
        return;

    device->StoreAddWatch("control/shutdown", m_evt_shutdown, &m_ctxt_shutdown);

    device->StoreWrite("control/feature-poweroff", "1");
    device->StoreWrite("control/feature-reboot", "1");
    device->StoreWrite("control/feature-s3", "1");
    device->StoreWrite("control/feature-s4", "1");
}

void CXenIfaceDeviceList::StopShutdownWatch(CXenIfaceDevice* device)
{
    if (!m_ctxt_shutdown)
        return;

    device->StoreWrite("control/feature-poweroff", "");
    device->StoreWrite("control/feature-reboot", "");
    device->StoreWrite("control/feature-s3", "");
    device->StoreWrite("control/feature-s4", "");

    device->StoreRemoveWatch(m_ctxt_shutdown);
    m_ctxt_shutdown = NULL;
}

void CXenIfaceDeviceList::StartSlateModeWatch(CXenIfaceDevice* device)
{
    if (m_ctxt_slate_mode)
        return;

    device->StoreAddWatch("control/laptop-slate-mode", m_evt_slate_mode, &m_ctxt_slate_mode);
    device->StoreWrite("control/feature-laptop-slate-mode", "1");
}

void CXenIfaceDeviceList::StopSlateModeWatch(CXenIfaceDevice* device)
{
    if (!m_ctxt_slate_mode)
        return;

    device->StoreRemove("control/feature-laptop-slate-mode");

    device->StoreRemoveWatch(m_ctxt_slate_mode);
    m_ctxt_slate_mode = NULL;
}

void CXenIfaceDeviceList::AcquireShutdownPrivilege()
{
    HANDLE          token;
    TOKEN_PRIVILEGES tp;

    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    tp.PrivilegeCount = 1;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token))
        return;

    AdjustTokenPrivileges(token, FALSE, &tp, NULL, 0, NULL);
    CloseHandle(token);
}

void CXenIfaceDeviceList::SetXenTime(CXenIfaceDevice* device)
{
    bool local;

    FILETIME now = { 0 };
    if (!device->SharedInfoGetTime(&now, &local))
        return;

    SYSTEMTIME cur = { 0 };
    if (local)
        GetLocalTime(&cur);
    else
        GetSystemTime(&cur);

    SYSTEMTIME sys = { 0 };
    if (!FileTimeToSystemTime(&now, &sys))
        return;

    if (memcmp(&cur, &sys, sizeof(SYSTEMTIME)) == 0)
        return;

    CXenAgent::Log("RTC is in %s\n", local ? "local time" : "UTC");
    CXenAgent::Log("Time Now = %d/%d/%d %d:%02d:%02d.%d\n",
                   cur.wYear, cur.wMonth, cur.wDay,
                   cur.wHour, cur.wMinute, cur.wSecond, cur.wMilliseconds);
    CXenAgent::Log("New Time = %d/%d/%d %d:%02d:%02d.%d\n",
                   sys.wYear, sys.wMonth, sys.wDay,
                   sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);

    if (local)
        SetLocalTime(&sys);
    else
        SetSystemTime(&sys);
}
