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
#include <stdio.h>
#include <powrprof.h>
#include <winuser.h>

#include "service.h"
#include "messages.h"
#include "xeniface_ioctls.h"

static CXenAgent s_service;

/*static*/ void CXenAgent::Log(const char* fmt, ...)
{
    char message[XENIFACE_LOG_MAX_LENGTH];
    va_list args;

    va_start(args, fmt);
    vsnprintf_s(message, sizeof(message), sizeof(message)/sizeof(message[0]) - 1, fmt, args);
    va_end(args);

    OutputDebugString(message);

    s_service.m_xeniface.Log(message);
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
        return -1;
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
        return -1;
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

#pragma warning(push)
#pragma warning(disable:4355)

CXenAgent::CXenAgent() noexcept : m_handle(NULL), m_evtlog(NULL),
    m_xeniface(this), m_conv(this)
{
    m_status.dwServiceType        = SERVICE_WIN32;
    m_status.dwCurrentState       = SERVICE_START_PENDING;
    m_status.dwControlsAccepted   = SERVICE_ACCEPT_STOP |
                                    SERVICE_ACCEPT_SHUTDOWN |
                                    SERVICE_ACCEPT_POWEREVENT;
    m_status.dwWin32ExitCode      = 0;
    m_status.dwServiceSpecificExitCode = 0;
    m_status.dwCheckPoint         = 0;
    m_status.dwWaitHint           = 0;

    m_svc_stop = CreateEvent(FALSE, NULL, NULL, FALSE);
}

#pragma warning(pop)

CXenAgent::~CXenAgent()
{
    CloseHandle(m_svc_stop);
}

void CXenAgent::OnServiceStart()
{
    CXenAgent::Log("OnServiceStart()\n");
    m_xeniface.RegisterForDeviceChange(m_handle);
    m_xeniface.EnumerateDevices();
    m_conv.EnumerateDevices();
}

void CXenAgent::OnServiceStop()
{
    CXenAgent::Log("OnServiceStop()\n");
    m_xeniface.LogIfRebootPending();
    m_xeniface.UnregisterForDeviceChange();
    m_xeniface.CleanupDeviceList();
    m_conv.CleanupDeviceList();
}

void CXenAgent::OnDeviceEvent(DWORD evt, LPVOID data)
{
    m_xeniface.OnDeviceEvent(evt, data);
}

void CXenAgent::OnPowerEvent(DWORD evt, LPVOID data)
{
    m_conv.OnPowerEvent(evt, data);
    m_xeniface.OnPowerEvent(evt, data);
}

bool CXenAgent::ServiceMainLoop()
{
    DWORD   timeout = 30 * 60 * 1000;
    HANDLE  events[] = { m_svc_stop,
                         m_xeniface.m_evt_shutdown,
                         m_xeniface.m_evt_suspend,
                         m_xeniface.m_evt_slate_mode };
    DWORD   wait = WaitForMultipleObjectsEx(4, events, FALSE, timeout, TRUE);

    switch (wait) {
    case WAIT_OBJECT_0:
        ResetEvent(m_svc_stop);
        return false; // exit loop

    case WAIT_OBJECT_0+1:
        ResetEvent(m_xeniface.m_evt_shutdown);
        return !m_xeniface.CheckShutdown();

    case WAIT_OBJECT_0+2:
        ResetEvent(m_xeniface.m_evt_suspend);
        m_xeniface.CheckXenTime();
        m_xeniface.CheckSuspend();
        return true; // continue loop

    case WAIT_OBJECT_0+3: {
        std::string mode;

        ResetEvent(m_xeniface.m_evt_slate_mode);
        if (m_xeniface.CheckSlateMode(mode))
            m_conv.SetSlateMode(mode);

        return true; // continue loop
    }
    case WAIT_TIMEOUT:
        m_xeniface.CheckXenTime();
        __fallthrough;
    case WAIT_IO_COMPLETION:
        m_xeniface.CheckSuspend();
        return !m_xeniface.CheckShutdown();

    default:
        CXenAgent::Log("WaitForMultipleObjects failed (%08x)\n", wait);
        EventLog(EVENT_XENUSER_UNEXPECTED);
        return true; // continue loop
    }
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

bool CXenAgent::ConvDevicePresent()
{
    return m_conv.GetFirstDevice() != NULL;
}

void CXenAgent::SetServiceStatus(DWORD state, DWORD exit /*= 0*/, DWORD hint /*= 0*/)
{
    m_status.dwCurrentState = state;
    m_status.dwWin32ExitCode = exit;
    m_status.dwWaitHint = hint;
    ::SetServiceStatus(m_handle, &m_status);
}

#pragma warning(push)
#pragma warning(disable: 28735) 
//	Temporary ignore warning C28735: Banned Crimson API Usage:  RegisterEventSourceA is a Banned Crimson API.
//	TODO: Replace with a safer API alternative and ensure compliance with security best practices.

void WINAPI CXenAgent::__ServiceMain(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

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

#pragma warning(pop)

DWORD WINAPI CXenAgent::__ServiceControlHandlerEx(DWORD req, DWORD evt, LPVOID data, LPVOID ctxt)
{
    UNREFERENCED_PARAMETER(ctxt);

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

    case SERVICE_CONTROL_POWEREVENT:
        SetServiceStatus(SERVICE_RUNNING);
        OnPowerEvent(evt, data);
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

int CALLBACK WinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevious,
    _In_     LPSTR     lpCmdLine,
    _In_     int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevious);
    UNREFERENCED_PARAMETER(nCmdShow);

    if (strlen(lpCmdLine) != 0) {
        if (!strcmp(lpCmdLine, "-i") || !strcmp(lpCmdLine, "\"-i\""))
            return CXenAgent::ServiceInstall();
        if (!strcmp(lpCmdLine, "-u") || !strcmp(lpCmdLine, "\"-u\""))
            return CXenAgent::ServiceUninstall();
    }
    return CXenAgent::ServiceEntry();
}
