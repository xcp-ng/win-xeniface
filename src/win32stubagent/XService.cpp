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
#include <shlobj.h>
#include <process.h>
#include "powrprof.h"
#include <winuser.h>
#include "stdafx.h"
#include "XSAccessor.h"
#include "WMIAccessor.h"
#include "XService.h"

#include "messages.h"

#include <setupapi.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>
#include <wintrust.h>
#include <shellapi.h>

#ifdef AMD64
#define XENTOOLS_INSTALL_REG_KEY "SOFTWARE\\Wow6432Node\\Citrix\\XenTools"
#else
#define XENTOOLS_INSTALL_REG_KEY "SOFTWARE\\Citrix\\XenTools"
#endif

SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus;  

static HANDLE hServiceExitEvent;
static ULONG WindowsVersion;
static BOOL LegacyHal = FALSE;
static HINSTANCE local_hinstance;

#define SIZECHARS(x) (sizeof((x))/sizeof(TCHAR))

// Internal routines
static DWORD WINAPI ServiceControlHandler(DWORD request, DWORD evtType,
                                          LPVOID, LPVOID);
static void ServiceControlManagerUpdate(DWORD dwExitCode, DWORD dwState);
static void WINAPI ServiceMain(int argc, char** argv);
static void GetWindowsVersion();

void PrintError(const char *func, DWORD err)
{
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0,
		NULL);
	OutputDebugString((LPTSTR)lpMsgBuf);
    XenstorePrintf("control/error", "%s failed: %s (%x)", func, lpMsgBuf, err);
	LocalFree(lpMsgBuf);
}

void PrintError(const char *func)
{
	PrintError(func, GetLastError());
}

void PrintUsage()
{
	printf("Usage: xenservice [-u]\n");

	printf("\t -u: uninstall service\n");
}



struct watch_event {
    HANDLE event;
    void *watch;
};

static void
ReleaseWatch(struct watch_event *we)
{
    if (we == NULL)
        return;
    if (we->event != INVALID_HANDLE_VALUE)
        CloseHandle(we->event);
    if (we->watch)
        XenstoreUnwatch(we->watch);
    free(we);
}

static struct watch_event *
EstablishWatch(const char *path, HANDLE errorevent)
{
    struct watch_event *we;
    DWORD err;
	XsLog("Establish watch %s",path);
    we = (struct watch_event *)malloc(sizeof(*we));
    if (!we) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memset(we, 0, sizeof(*we));
    we->watch = NULL;
    we->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (we->event != INVALID_HANDLE_VALUE)
        we->watch = XenstoreWatch(path, we->event, errorevent);
    if (we->watch == NULL) {
		OutputDebugString("Watch is null\n");
        err = GetLastError();
        ReleaseWatch(we);
        SetLastError(err);
        return NULL;
    }
    return we;
}

struct watch_feature {
    struct watch_event *watch;
    const char *feature_flag;
    const char *name;
    BOOL (*handler)(void *);
    void *ctx;
};

#define MAX_FEATURES 10
struct watch_feature_set {
    struct watch_feature features[MAX_FEATURES];
    unsigned nr_features;
};

static BOOL
AddFeature(struct watch_feature_set *wfs, const char *path,
           const char *flag, const char *name,
           BOOL (*handler)(void *), void *ctx, HANDLE errorevent)
{
    unsigned n;
    if (wfs->nr_features == MAX_FEATURES) {
        PrintError("Too many features!", ERROR_INVALID_FUNCTION);
        return false;
    }
    n = wfs->nr_features;
    wfs->features[n].watch = EstablishWatch(path, errorevent);
    if (wfs->features[n].watch == NULL) {
        PrintError("EstablishWatch() for AddFeature()");
        return false;
    }
    wfs->features[n].feature_flag = flag;
    wfs->features[n].handler = handler;
    wfs->features[n].ctx = ctx;
    wfs->features[n].name = name;
    wfs->nr_features++;
	return true;
}

static void RemoveFeatures(struct watch_feature_set *wfs) {
	unsigned x;
    for (x = 0; x < wfs->nr_features; x++) {
		ReleaseWatch(wfs->features[x].watch);
		wfs->features[x].watch = NULL;
		XenstoreRemove(wfs->features[x].feature_flag);
	}
	wfs->nr_features = 0;
}

static BOOL
AdvertiseFeatures(struct watch_feature_set *wfs)
{
    unsigned x;
    for (x = 0; x < wfs->nr_features; x++) {
        if (wfs->features[x].feature_flag != NULL)
            if (XenstorePrintf(wfs->features[x].feature_flag, "1"))
				return false;
    }
	return true;
}


void ServiceUninstall()
{
	SC_HANDLE   hSvc;
	SC_HANDLE   hMgr;
	
	hMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if ( hMgr )
	{
		hSvc = OpenService(hMgr, SVC_NAME, SERVICE_ALL_ACCESS);

		if (hSvc)
		{
			 // try to stop the service
			 if ( ControlService( hSvc, SERVICE_CONTROL_STOP, &ServiceStatus ) )
			 {
				printf("Stopping %s.", SVC_DISPLAYNAME);
				Sleep( 1000 );

				while ( QueryServiceStatus( hSvc, &ServiceStatus ) )
				{
					if ( ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING )
					{
						printf(".");
						Sleep( 1000 );
					}
					else
						break;
				}

				if ( ServiceStatus.dwCurrentState == SERVICE_STOPPED )
					printf("\n%s stopped.\n", SVC_DISPLAYNAME );
				else
					printf("\n%s failed to stop.\n", SVC_DISPLAYNAME );
         }

         // now remove the service
         if ( DeleteService(hSvc) )
            printf("%s uninstalled.\n", SVC_DISPLAYNAME );
         else
            printf("Unable to uninstall - %d\n", GetLastError());

         CloseServiceHandle(hSvc);

      }
      else
         printf("Unable to open service - %d\n", GetLastError());

      CloseServiceHandle(hMgr);
   }
   else
      printf("Unable to open scm - %d\n", GetLastError());

}


int __stdcall
WinMain(HINSTANCE hInstance, HINSTANCE ignore,
        LPSTR lpCmdLine, int nCmdShow)
{
    local_hinstance = hInstance;

    if (strlen(lpCmdLine) == 0) {
		SERVICE_TABLE_ENTRY ServiceTable[2];
		ServiceTable[0].lpServiceName = SVC_NAME;
		ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

		ServiceTable[1].lpServiceName = NULL;
		ServiceTable[1].lpServiceProc = NULL;

		DBGPRINT(("XenSvc: starting ctrl dispatcher "));

		// Start the control dispatcher thread for our service
		if (!StartServiceCtrlDispatcher(ServiceTable))
		{
			int err = GetLastError();
			if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			{
				DBGPRINT(("XenSvc: unable to start ctrl dispatcher - %d", GetLastError()));
			}
		}
		else
		{
			// We get here when the service is shut down.
		}
    } else if (!strcmp(lpCmdLine, "-u") || !strcmp(lpCmdLine, "\"-u\"")) {
        ServiceUninstall();
    } else {
        PrintUsage();
    }

    return 0;
}

void AcquireSystemPrivilege(LPCTSTR name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tkp;
    DWORD err;

    LookupPrivilegeValue(NULL, name, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
                          &token)) {
        DBGPRINT(("Failed to open local token.\n"));
    } else {
        AdjustTokenPrivileges(token, FALSE, &tkp,
                              NULL, 0, NULL);
        err = GetLastError();
        if (err != ERROR_SUCCESS) {
            PrintError("AdjustTokenPrivileges", err);
        }
    }
}

static void AcquireSystemShutdownPrivilege(void)
{
    AcquireSystemPrivilege(SE_SHUTDOWN_NAME);
}

enum XShutdownType {
	XShutdownPoweroff,
	XShutdownReboot,
	XShutdownSuspend,
    XShutdownS3
};

static BOOL maybeReboot(void *ctx)
{
	char *shutdown_type;
	BOOL res;
	enum XShutdownType type;
    int cntr = 0;
    HANDLE eventLog;

	if (XenstoreRead("control/shutdown", &shutdown_type) < 0)
		return true;
	DBGPRINT(("Shutdown type %s\n", shutdown_type));
	if (strcmp(shutdown_type, "poweroff") == 0 ||
	    strcmp(shutdown_type, "halt") == 0) {
		type = XShutdownPoweroff;
	} else if (strcmp(shutdown_type, "reboot") == 0) {
		type = XShutdownReboot;
	} else if (strcmp(shutdown_type, "hibernate") == 0) {
		type = XShutdownSuspend;
	} else if (strcmp(shutdown_type, "s3") == 0) {
		type = XShutdownS3;
	} else {
		DBGPRINT(("Bad shutdown type %s\n", shutdown_type));
		goto out;
	}

	/* We try to shutdown even if this fails, since it might work
	   and it can't do any harm. */
	AcquireSystemShutdownPrivilege();

    eventLog = RegisterEventSource(NULL, "xensvc");
    if (eventLog) {
        DWORD eventId;

        switch (type) {
        case XShutdownPoweroff:
            eventId = EVENT_XENUSER_POWEROFF;
            break;
        case XShutdownReboot:
            eventId = EVENT_XENUSER_REBOOT;
            break;
        case XShutdownSuspend:
            eventId = EVENT_XENUSER_HIBERNATE;
            break;
        case XShutdownS3:
            eventId = EVENT_XENUSER_S3;
            break;
        }
        ReportEvent(eventLog, EVENTLOG_SUCCESS, 0, eventId, NULL, 0, 0,
                    NULL, NULL);
        DeregisterEventSource(eventLog);
    }
	/* do the shutdown */
	switch (type) {
	case XShutdownPoweroff:
	case XShutdownReboot:
        if (WindowsVersion >= 0x500 && WindowsVersion < 0x600)
        {
            /* Windows 2000 InitiateSystemShutdownEx is funny in
               various ways (e.g. sometimes fails to power off after
               shutdown, especially if the local terminal is locked,
               not doing anything if there's nobody logged on, etc.).
               ExitWindowsEx seems to be more reliable, so use it
               instead. */
            /* XXX I don't really understand why
               InitiateSystemShutdownEx behaves so badly. */
            /* If this is a legacy hal then use EWX_SHUTDOWN when shutting
               down instead of EWX_POWEROFF. */
	    /* Similar problem on XP. Shutdown/Reboot will hang until the Welcome
		screen screensaver is dismissed by the guest */
#pragma warning (disable : 28159)
            res = ExitWindowsEx((type == XShutdownReboot ? 
                                    EWX_REBOOT : 
                                    (LegacyHal ? 
                                        EWX_SHUTDOWN :
                                        EWX_POWEROFF))|
                                EWX_FORCE,
                                SHTDN_REASON_MAJOR_OTHER|
                                SHTDN_REASON_MINOR_ENVIRONMENT |
                                SHTDN_REASON_FLAG_PLANNED);
#pragma warning (default: 28159)
            if (!res) {
                PrintError("ExitWindowsEx");
				return false;
			}
            else
            {
				if (XenstoreRemove("control/shutdown"))
					return false;
			}
        } else {
#pragma warning (disable : 28159)
            res = InitiateSystemShutdownEx(
                NULL,
                NULL,
                0,
                TRUE,
                type == XShutdownReboot,
                SHTDN_REASON_MAJOR_OTHER |
                SHTDN_REASON_MINOR_ENVIRONMENT |
                SHTDN_REASON_FLAG_PLANNED);
#pragma warning (default: 28159)
            if (!res) {
                PrintError("InitiateSystemShutdownEx");
				return false;
            } else {
                if (XenstoreRemove("control/shutdown"))
					return false;
            }
        }
		break;
	case XShutdownSuspend:
        if (XenstorePrintf ("control/hibernation-state", "started"))
			return false;
        /* Even if we think hibernation is disabled, try it anyway.
           It's not like it can do any harm. */
		res = SetSystemPowerState(FALSE, FALSE);
        if (XenstoreRemove ("control/shutdown"))
		{ 
			return false;	
		}
        if (!res) {
            /* Tell the tools that we've failed. */
            PrintError("SetSystemPowerState");
            if (XenstorePrintf ("control/hibernation-state", "failed"))
				return false;
        }
		break;
    case XShutdownS3:
        if (XenstorePrintf ("control/s3-state", "started"))
			return false;
        res = SetSuspendState(FALSE, TRUE, FALSE);
        XenstoreRemove ("control/shutdown");
        if (!res) {
            PrintError("SetSuspendState");
            if (XenstorePrintf ("control/s3-state", "failed"))
				return false;
        }
        break;
	}

out:
	XenstoreFree(shutdown_type);
	return true;
}

/* We need to resync the clock when we recover from suspend/resume. */
static void
finishSuspend(void)
{
    FILETIME now = {0};
    SYSTEMTIME sys_time;
    SYSTEMTIME current_time;

    DBGPRINT(("Coming back from suspend.\n"));
    GetXenTime(&now);
	if ((now.dwLowDateTime == 0) && (now.dwHighDateTime == 0)) {
		XsLog("Cannot set system time to xentime, unable to contact WMI");
		return;
	}
    XsLog("Xen time is %I64x", now);
    if (!FileTimeToSystemTime(&now, &sys_time)) {
        PrintError("FileTimeToSystemTime()");
        DBGPRINT(("FileTimeToSystemTime(%x.%x)\n",
                  now.dwLowDateTime, now.dwHighDateTime));
    } else {
        XsLog("Set time to %d.%d.%d %d:%d:%d.%d",
              sys_time.wYear, sys_time.wMonth, sys_time.wDay,
              sys_time.wHour, sys_time.wMinute, sys_time.wSecond,
              sys_time.wMilliseconds);
        GetLocalTime(&current_time);
        XsLog("Time is now  %d.%d.%d %d:%d:%d.%d",
              current_time.wYear, current_time.wMonth, current_time.wDay,
              current_time.wHour, current_time.wMinute, current_time.wSecond,
              current_time.wMilliseconds);
        if (!SetLocalTime(&sys_time))
            PrintError("SetSystemTime()");
    }
}



//
// Main loop
//
BOOL Run()
{
    bool exit=false;
    PCHAR pPVAddonsInstalled = NULL;

    HANDLE suspendEvent;

    int cntr = 0;
    struct watch_feature_set features;
    BOOL snap = FALSE;

	OutputDebugString("Trying to connect to WMI\n");
	while (!ConnectToWMI()) {
		OutputDebugString("Unable to connect to WMI, sleeping\n");
		if (WaitForSingleObject(hServiceExitEvent, 1000*10) == WAIT_OBJECT_0) {
			exit = true;
			return exit;
		}
	}
	while (InitXSAccessor()==false) {
		OutputDebugString("Unable to initialise WMI session, sleeping\n");
		if (WaitForSingleObject(hServiceExitEvent, 1000*10) == WAIT_OBJECT_0) {
			exit = true;
			return exit;
		}
	}
    XsLogMsg("Guest agent lite main loop starting");

    memset(&features, 0, sizeof(features));

	HANDLE wmierrorEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!wmierrorEvent) {
        PrintError("CreateEvent() wmierrorEvent");
		return exit;
    }
   

    XsLogMsg("About to add feature shutdown");
    if (!AddFeature(&features, "control/shutdown", "control/feature-shutdown", 
					"shutdown", maybeReboot, NULL, wmierrorEvent)) {
		return exit;
	}

    suspendEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!suspendEvent) {
        PrintError("CreateEvent() suspendEvent");
		return exit;
    }
    
	if (ListenSuspend(suspendEvent, wmierrorEvent) < 0) {
		PrintError("ListenSuspend()");
		CloseHandle(suspendEvent);
		suspendEvent = NULL;
		return exit;
    }


    XsLogMsg("About to advertise features");
    AdvertiseFeatures(&features);
    XsLogMsg("About to kick xapi ");
	XenstoreKickXapi();

    while (1)
    {
        DWORD status;
        int nr_handles = 1;
        HANDLE handles[3 + MAX_FEATURES];
        unsigned x;

        handles[0] = hServiceExitEvent;
		if (wmierrorEvent)
			handles[nr_handles++] = wmierrorEvent;
        if (suspendEvent)
            handles[nr_handles++] = suspendEvent;
        for (x = 0; x < features.nr_features; x++)
            handles[nr_handles++] = features.features[x].watch->event;

        XsLogMsg("win agent going to sleep");
        status = WaitForMultipleObjects(nr_handles, handles, FALSE, INFINITE);
        XsLogMsg("win agent woke up for %d", status);

        /* WAIT_OBJECT_0 happens to be 0, so the compiler gets shirty
           about status >= WAIT_OBJECT_0 (since status is unsigned).
           This is more obviously correct than the compiler-friendly
           version, though, so just disable the warning. */

#pragma warning (disable: 4296)
        if (status >= WAIT_OBJECT_0 &&
            status < WAIT_OBJECT_0 + nr_handles)
#pragma warning (default: 4296)
        {
            HANDLE event = handles[status - WAIT_OBJECT_0];
            if (event == hServiceExitEvent)
            {
				OutputDebugString("Service Exit fired\n");
                XsLogMsg("service exit event");
				exit = true;
                break;
            }
            else if (event == suspendEvent)
            {
				OutputDebugString("Suspend fired\n");
                XsLogMsg("Suspend event");
                finishSuspend();
                AdvertiseFeatures(&features);
				XenstoreKickXapi();
                XsLogMsg("Handled suspend event");
            }
			else if (event == wmierrorEvent)
			{
				break;
			}
            else
            {
				OutputDebugString("Feature fired\n");
				BOOL fail = false;
                for (x = 0; x < features.nr_features; x++) {
                    if (features.features[x].watch->event == event) {
                        XsLogMsg("fire feature %s", features.features[x].name);
						OutputDebugString("Event triggered\n");
                        if (!(features.features[x].handler(features.features[x].ctx)))
						{
							PrintError("Feature failed");
							fail = true;
						}
                        XsLogMsg("fired feature %s",
                                 features.features[x].name);
                    }
                }
				if (fail)
					break;
            }
        }
        else
        {
            PrintError("WaitForMultipleObjects()");
            break;
        }
    }
	OutputDebugString("WMI Watch loop terminated\n");
	RemoveFeatures(&features);
	XenstoreKickXapi();

    XsLogMsg("Guest agent lite loop finishing");
    ReleaseWMIAccessor(&wmi);


  

    XsLogMsg("Guest agent lite loop finished %d", exit);
	return exit;
}


// Service initialization
bool ServiceInit()
{
	ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   =
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
        SERVICE_ACCEPT_SESSIONCHANGE;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandlerEx(
		"XenService", 
		ServiceControlHandler,
        NULL);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) 
    { 
        // Registering Control Handler failed
		DBGPRINT(("XenSvc: Registering service control handler failed - %d\n", GetLastError()));
        return false; 
    }  

	ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
	SetServiceStatus (hStatus, &ServiceStatus);

	return true;
}

void WINAPI ServiceMain(int argc, char** argv)
{
    // Perform common initialization
    hServiceExitEvent = CreateEvent(NULL, false, false, NULL);
    if (hServiceExitEvent == NULL)
    {
        DBGPRINT(("XenSvc: Unable to create the event obj - %d\n", GetLastError()));
        return;
    }

    if (!ServiceInit())
    {
        DBGPRINT(("XenSvc: Unable to init xenservice\n"));
        return;
    }
	BOOL stopping;

	do {
		
		__try
		{
			stopping = Run();
			
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
		}
	} while (!stopping);
	
    XsLog("Guest agent service stopped");
    ShutdownXSAccessor();
	ServiceControlManagerUpdate(0, SERVICE_STOPPED);
    return;
}

void ServiceControlManagerUpdate(DWORD dwExitCode, DWORD dwState)
{
    ServiceStatus.dwWin32ExitCode = dwExitCode; 
    ServiceStatus.dwCurrentState  = dwState; 
    SetServiceStatus (hStatus, &ServiceStatus);
}

// Service control handler function
static DWORD WINAPI ServiceControlHandler(DWORD request, DWORD evtType,
                                          LPVOID eventData, LPVOID ctxt)
{
    UNREFERENCED_PARAMETER(ctxt);
    UNREFERENCED_PARAMETER(eventData);

    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 
            DBGPRINT(("XenSvc: xenservice stopped.\n"));
            ServiceControlManagerUpdate(0, SERVICE_STOP_PENDING);
            SetEvent(hServiceExitEvent);
            return NO_ERROR;
 
        case SERVICE_CONTROL_SHUTDOWN: 
            DBGPRINT(("XenSvc: xenservice shutdown.\n"));
            ServiceControlManagerUpdate(0, SERVICE_STOP_PENDING);
            SetEvent(hServiceExitEvent);
            return NO_ERROR;

        default:
	    DBGPRINT(("XenSvc: unknown request."));
            break;
    } 

    ServiceControlManagerUpdate(0, SERVICE_RUNNING);
    return ERROR_CALL_NOT_IMPLEMENTED;
}
