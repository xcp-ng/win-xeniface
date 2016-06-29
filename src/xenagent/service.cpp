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
#include <stdio.h>
#include <powrprof.h>
#include <winuser.h>

#include <xeniface_ioctls.h>

#include "service.h"
#include "messages.h"

class CCritSec
{
public:
    CCritSec(LPCRITICAL_SECTION crit);
    ~CCritSec();
private:
    LPCRITICAL_SECTION m_crit;
};

CCritSec::CCritSec(LPCRITICAL_SECTION crit) : m_crit(crit)
{
    EnterCriticalSection(m_crit);
}
CCritSec::~CCritSec()
{
    LeaveCriticalSection(m_crit);
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE ignore, LPSTR lpCmdLine, int nCmdShow)
{
    if (strlen(lpCmdLine) != 0) {
        if (!strcmp(lpCmdLine, "-i") || !strcmp(lpCmdLine, "\"-i\""))
            return CXenAgent::ServiceInstall();
        if (!strcmp(lpCmdLine, "-u") || !strcmp(lpCmdLine, "\"-u\""))
            return CXenAgent::ServiceUninstall();
    }
    return CXenAgent::ServiceEntry();
}

static CXenAgent s_service;

/*static*/ void CXenAgent::Log(const char* fmt, ...)
{
    char message[XENIFACE_LOG_MAX_LENGTH];
    va_list args;

    va_start(args, fmt);
    vsnprintf_s(message, sizeof(message), sizeof(message)/sizeof(message[0]) - 1, fmt, args);
    va_end(args);

    OutputDebugString(message);
}

/*static*/ int CXenAgent::ServiceInstall()
{
    SC_HANDLE   svc, mgr;
    char        path[MAX_PATH+1];

    mgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (mgr == NULL)
        return -1;

    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
        CloseServiceHandle(mgr);
        return GetLastError();
    }
    path[MAX_PATH] = 0;

    svc = CreateServiceA(mgr, SVC_NAME, SVC_DISPLAYNAME, SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL, path,
                        NULL, NULL, NULL, NULL, NULL);
    if (svc == NULL) {
        CloseServiceHandle(mgr);
        return -2;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(mgr);
    return 0;
}

/*static*/ int CXenAgent::ServiceUninstall()
{
    SC_HANDLE   svc, mgr;

    mgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (mgr == NULL)
        return -1;

    svc = OpenService(mgr, SVC_NAME, SERVICE_ALL_ACCESS);
    if (svc == NULL) {
        CloseServiceHandle(mgr);
        return -2;
    }

    // try to stop the service
    if (ControlService(svc, SERVICE_CONTROL_STOP, &s_service.m_status))
    {
        Sleep( 1000 );

        while (QueryServiceStatus(svc, &s_service.m_status))
        {
            if (s_service.m_status.dwCurrentState != SERVICE_STOP_PENDING)
                break;
            Sleep(1000);
        }
    }

    // now remove the service
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(mgr);
    return 0;
}

/*static*/ int CXenAgent::ServiceEntry()
{
    SERVICE_TABLE_ENTRY ServiceTable[2] =
    {
        { SVC_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        CXenAgent::Log("Failed to start dispatcher\n");
        return GetLastError();
    }
    return 0;
}

/*static*/ void WINAPI CXenAgent::ServiceMain(int argc, char** argv)
{
    s_service.__ServiceMain(argc, argv);
}

/*static*/ DWORD WINAPI CXenAgent::ServiceControlHandlerEx(DWORD req, DWORD evt, LPVOID data, LPVOID ctxt)
{
    return s_service.__ServiceControlHandlerEx(req, evt, data, ctxt);
}

CXenAgent::CXenAgent() : m_handle(NULL), m_evtlog(NULL),
    m_devlist(GUID_INTERFACE_XENIFACE), m_device(NULL),
    m_ctxt_shutdown(NULL), m_ctxt_suspend(NULL)
{
    m_status.dwServiceType        = SERVICE_WIN32;
    m_status.dwCurrentState       = SERVICE_START_PENDING;
    m_status.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    m_status.dwWin32ExitCode      = 0;
    m_status.dwServiceSpecificExitCode = 0;
    m_status.dwCheckPoint         = 0;
    m_status.dwWaitHint           = 0;

    m_svc_stop = CreateEvent(FALSE, NULL, NULL, FALSE);
    m_evt_shutdown = CreateEvent(FALSE, NULL, NULL, FALSE);
    m_evt_suspend = CreateEvent(FALSE, NULL, NULL, FALSE);

    InitializeCriticalSection(&m_crit);
}

CXenAgent::~CXenAgent()
{
    CloseHandle(m_evt_suspend);
    CloseHandle(m_evt_shutdown);
    CloseHandle(m_svc_stop);

    DeleteCriticalSection(&m_crit);
}

/*virtual*/ CDevice* CXenAgent::Create(const wchar_t* path)
{
    return new CXenIfaceDevice(path);
}

/*virtual*/ void CXenAgent::OnDeviceAdded(CDevice* dev)
{
    CXenAgent::Log("OnDeviceAdded(%ws)\n", dev->Path());

    CCritSec crit(&m_crit);
    if (m_device == NULL) {
        m_device = (CXenIfaceDevice*)dev;

        // shutdown
        m_device->StoreAddWatch("control/shutdown", m_evt_shutdown, &m_ctxt_shutdown);
        m_device->StoreWrite("control/feature-shutdown", "1");

        // suspend
        m_device->SuspendRegister(m_evt_suspend, &m_ctxt_suspend);

        SetXenTime();
    }
}

/*virtual*/ void CXenAgent::OnDeviceRemoved(CDevice* dev)
{
    CXenAgent::Log("OnDeviceRemoved(%ws)\n", dev->Path());

    CCritSec crit(&m_crit);
    if (m_device == dev) {
        // suspend
        if (m_ctxt_suspend)
            m_device->SuspendDeregister(m_ctxt_suspend);
        m_ctxt_suspend = NULL;

        // shutdown
        m_device->StoreRemove("control/feature-shutdown");
        if (m_ctxt_shutdown)
            m_device->StoreRemoveWatch(m_ctxt_shutdown);
        m_ctxt_shutdown = NULL;

        m_device = NULL;
    }
}

void CXenAgent::OnServiceStart()
{
    CXenAgent::Log("OnServiceStart()\n");
    m_devlist.Start(m_handle, this);
}

void CXenAgent::OnServiceStop()
{
    CXenAgent::Log("OnServiceStop()\n");
    m_devlist.Stop();
}

void CXenAgent::OnDeviceEvent(DWORD evt, LPVOID data)
{
    m_devlist.OnDeviceEvent(evt, data);
}

bool CXenAgent::ServiceMainLoop()
{
    HANDLE  events[3] = { m_svc_stop, m_evt_shutdown, m_evt_suspend };
    DWORD   wait = WaitForMultipleObjects(3, events, FALSE, INFINITE);

    switch (wait) {
    case WAIT_OBJECT_0:
        return false; // exit loop

    case WAIT_OBJECT_0+1:
        OnShutdown();
        return true; // continue loop

    case WAIT_OBJECT_0+2:
        OnSuspend();
        return true; // continue loop

    default:
        CXenAgent::Log("WaitForMultipleObjects failed (%08x)\n", wait);
        EventLog(EVENT_XENUSER_UNEXPECTED);
        return true; // continue loop
    }
}

void CXenAgent::AcquireShutdownPrivilege()
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

void CXenAgent::EventLog(DWORD evt)
{
    if (m_evtlog) {
        ReportEvent(m_evtlog,
                    EVENTLOG_SUCCESS,
                    0,
                    evt,
                    NULL,
                    0,
                    0,
                    NULL,
                    NULL);
    }
}

bool CXenAgent::IsHostTimeUTC()
{
#ifdef _WIN64
    // Check SOFTWARE\Wow6432Node\$(VENDOR_NAME_STR)\$(REG_KEY_NAME) $(REG_UTC_NAME) == UTC
    if (RegCheckIsUTC("SOFTWARE\\Wow6432Node"))
        return true;
#endif
    // Check SOFTWARE\$(VENDOR_NAME_STR)\$(REG_KEY_NAME) $(REG_UTC_NAME) == UTC
    if (RegCheckIsUTC("SOFTWARE"))
        return true;

    return false;
}

void CXenAgent::AdjustXenTimeToUTC(FILETIME* now)
{
    std::string vm;
    if (!m_device->StoreRead("vm", vm))
        return;

    std::string offs;
    if (!m_device->StoreRead(vm + "/rtc/timeoffset", offs))
        return;

    long offset = (long)atoi(offs.c_str());

    ULARGE_INTEGER lnow;
    lnow.LowPart  = now->dwLowDateTime;
    lnow.HighPart = now->dwHighDateTime;

    lnow.QuadPart -= ((LONGLONG)offset * 1000000);

    now->dwLowDateTime  = lnow.LowPart;
    now->dwHighDateTime = lnow.HighPart;
}

bool CXenAgent::RegCheckIsUTC(const char* rootpath)
{
    HKEY    key;
    LRESULT lr;
    std::string path;
    bool    match = false;

    path = rootpath;
    path += "\\";
    path += VENDOR_NAME_STR;
    path += "\\";
    path += REG_KEY_NAME;

    lr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &key);
    if (lr != ERROR_SUCCESS)
        goto fail1;

    long size = 32;
    DWORD length;
    char* buffer = NULL;

    do {
        length = size;
        if (buffer)
            delete [] buffer;

        buffer = new char[size];
        if (buffer == NULL)
            goto fail2;

        lr = RegQueryValueEx(key, "HostTime", NULL, NULL, (LPBYTE)buffer, &length);
        size *= 2;
    } while (lr == ERROR_MORE_DATA);
    if (lr != ERROR_SUCCESS)
        goto fail3;

    if (!_strnicoll("UTC", buffer, length))
        match = true;

fail3:
    delete [] buffer;
fail2:
    RegCloseKey(key);
fail1:

    return match;
}

void CXenAgent::SetXenTime()
{
    // Set VM's time to Xen's time (adjust for UTC settings of VM and guest)
    FILETIME now = { 0 };
    if (!m_device->SharedInfoGetTime(&now))
        return;

    bool IsUTC = IsHostTimeUTC();
    if (IsUTC)
        AdjustXenTimeToUTC(&now);

    SYSTEMTIME sys = { 0 };
    if (!FileTimeToSystemTime(&now, &sys))
        return;

    SYSTEMTIME cur = { 0 };
    GetLocalTime(&cur);

    CXenAgent::Log("Time Now = %d/%d/%d %d:%02d:%02d.%d\n",
                   cur.wYear, cur.wMonth, cur.wDay,
                   cur.wHour, cur.wMinute, cur.wSecond, cur.wMilliseconds);
    CXenAgent::Log("New Time = %d/%d/%d %d:%02d:%02d.%d\n",
                   sys.wYear, sys.wMonth, sys.wDay,
                   sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);

    if (IsUTC)
        SetSystemTime(&sys);
    else
        SetLocalTime(&sys);
}

void CXenAgent::OnShutdown()
{
    CCritSec crit(&m_crit);
    if (m_device == NULL)
        return;

    std::string type;
    m_device->StoreRead("control/shutdown", type);

    CXenAgent::Log("OnShutdown(%ws) = %s\n", m_device->Path(), type.c_str());

    if (type == "poweroff" || type == "halt") {
        EventLog(EVENT_XENUSER_POWEROFF);

        m_device->StoreWrite("control/shutdown", "");
        AcquireShutdownPrivilege();
        if (!InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, FALSE,
                                      SHTDN_REASON_MAJOR_OTHER |
                                      SHTDN_REASON_MINOR_ENVIRONMENT |
                                      SHTDN_REASON_FLAG_PLANNED)) {
            CXenAgent::Log("InitiateSystemShutdownEx failed %08x\n", GetLastError());
        }
    } else if (type == "reboot") {
        EventLog(EVENT_XENUSER_REBOOT);

        m_device->StoreWrite("control/shutdown", "");
        AcquireShutdownPrivilege();
        if (!InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, TRUE,
                                      SHTDN_REASON_MAJOR_OTHER |
                                      SHTDN_REASON_MINOR_ENVIRONMENT |
                                      SHTDN_REASON_FLAG_PLANNED)) {
            CXenAgent::Log("InitiateSystemShutdownEx failed %08x\n", GetLastError());
        }
    } else if (type == "hibernate") {
        EventLog(EVENT_XENUSER_HIBERNATE);

        m_device->StoreWrite("control/shutdown", "");
        AcquireShutdownPrivilege();
        if (!SetSystemPowerState(FALSE, FALSE)) {
            CXenAgent::Log("SetSystemPowerState failed %08x\n", GetLastError());
        }
    } else if (type == "s3") {
        EventLog(EVENT_XENUSER_S3);

        m_device->StoreWrite("control/shutdown", "");
        AcquireShutdownPrivilege();
        if (!SetSuspendState(FALSE, TRUE, FALSE)) {
            CXenAgent::Log("SetSuspendState failed %08x\n", GetLastError());
        }
    }
}

void CXenAgent::OnSuspend()
{
    CCritSec crit(&m_crit);
    if (m_device == NULL)
        return;

    CXenAgent::Log("OnSuspend(%ws)\n", m_device->Path());
    EventLog(EVENT_XENUSER_UNSUSPENDED);

    m_device->StoreWrite("control/feature-shutdown", "1");

    SetXenTime();
}

void CXenAgent::SetServiceStatus(DWORD state, DWORD exit /*= 0*/, DWORD hint /*= 0*/)
{
    m_status.dwCurrentState = state;
    m_status.dwWin32ExitCode = exit;
    m_status.dwWaitHint = hint;
    ::SetServiceStatus(m_handle, &m_status);
}

void WINAPI CXenAgent::__ServiceMain(int argc, char** argv)
{
    m_handle = RegisterServiceCtrlHandlerEx(SVC_NAME, ServiceControlHandlerEx, NULL);
    if (m_handle == NULL)
        return;

    m_evtlog = RegisterEventSource(NULL, SVC_NAME);
    SetServiceStatus(SERVICE_RUNNING);

    OnServiceStart();
    while (ServiceMainLoop()) ;
    OnServiceStop();

    if (m_evtlog)
        DeregisterEventSource(m_evtlog);
    m_evtlog = NULL;
    SetServiceStatus(SERVICE_STOPPED);
}

DWORD WINAPI CXenAgent::__ServiceControlHandlerEx(DWORD req, DWORD evt, LPVOID data, LPVOID ctxt)
{
    switch (req)
    {
    case SERVICE_CONTROL_STOP:
        SetServiceStatus(SERVICE_STOP_PENDING);
        SetEvent(m_svc_stop);
        return NO_ERROR;

    case SERVICE_CONTROL_SHUTDOWN:
        SetServiceStatus(SERVICE_STOP_PENDING);
        SetEvent(m_svc_stop);
        return NO_ERROR;

    case SERVICE_CONTROL_DEVICEEVENT:
        SetServiceStatus(SERVICE_RUNNING);
        OnDeviceEvent(evt, data);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(SERVICE_RUNNING);
        return NO_ERROR;

    default:
        break;
    }

    SetServiceStatus(SERVICE_RUNNING);
    return ERROR_CALL_NOT_IMPLEMENTED;
}
