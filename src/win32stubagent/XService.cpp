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
#include <powrprof.h>
#include <winuser.h>
#include "stdafx.h"
#include "XSAccessor.h"
#include "WMIAccessor.h"
#include "XService.h"
#include "vm_stats.h"
#include "NicInfo.h"

//#include "xs_private.h"
#include "version.h"
#include "messages.h"
#include "TSInfo.h"

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
	DBGPRINT(("%s failed: %s (%lx)\n", func, lpMsgBuf, err));
    XenstorePrintf("control/error", "%s failed: %s (%x)", func, lpMsgBuf, err);
	LocalFree(lpMsgBuf);
}

void PrintError(const char *func)
{
	PrintError(func, GetLastError());
}

void PrintUsage()
{
	printf("Usage: xenservice [-i|-u|-c|-t]\n");
	printf("\t -i: install service\n");
	printf("\t -u: uninstall service\n");
}

HMODULE SLC_API;
HMODULE SLWGA_API;

typedef HRESULT (WINAPI *SL_GET_WINDOWS_INFORMATION_DWORD)(
    __in    PCWSTR  pwszValueName,
    __out   DWORD   *pdwValue
    );

typedef GUID SLID;

typedef enum _SL_GENUINE_STATE {
  SL_GEN_STATE_IS_GENUINE        = 0,
  SL_GEN_STATE_INVALID_LICENSE   = 1,
  SL_GEN_STATE_TAMPERED          = 2,
  SL_GEN_STATE_LAST              = 3 
} SL_GENUINE_STATE;

typedef HRESULT (WINAPI *SL_IS_GENUINE_LOCAL)(
    __in        const SLID                  *pAppId,
    __out       SL_GENUINE_STATE            *pGenuineState,
    __inout_opt VOID                        *pUnused
    );

/* Add operating system version, service pack, etc. to store. */
static VOID
AddSystemInfoToStore(
    WMIAccessor* wmi
    )
{
    OSVERSIONINFOEX info;
    char buf[MAX_PATH];
    
    XenstorePrintf("attr/os/class", "windows NT");
    /* Windows version, service pack, build number */
    info.dwOSVersionInfoSize = sizeof(info);
    if (GetVersionEx((LPOSVERSIONINFO)&info)) {
#define do_field(name, field) \
        XenstorePrintf("attr/os/" #name , "%d", info. field)
        do_field(major, dwMajorVersion);
        do_field(minor, dwMinorVersion);
        do_field(build, dwBuildNumber);
        do_field(platform, dwPlatformId);
        do_field(spmajor, wServicePackMajor);
        do_field(spminor, wServicePackMinor);
        do_field(suite, wSuiteMask);
        do_field(type, wProductType);
#undef do_field

        XenstorePrintf("data/os_distro", "windows");
        XenstorePrintf("data/os_majorver", "%d", info.dwMajorVersion);
        XenstorePrintf("data/os_minorver", "%d", info.dwMinorVersion);
    } else {
        /* Flag that we couldn't collect this information. */
        XenstorePrintf("attr/os/major", "-1");
    }

    DumpOSData(wmi);

    XenstorePrintf("attr/os/boottype", "%d", GetSystemMetrics(SM_CLEANBOOT));
    /* HAL version in use */
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_SYSTEM, NULL, SHGFP_TYPE_CURRENT, buf))) {
        DWORD tmp;
        DWORD versize;
        LPVOID buffer = NULL;
        TCHAR buffer2[128];
        LPTSTR halname;
        UINT halnamelen;
        struct {
            WORD language, code_page;
        } *trans;
        UINT trans_size;

        XenstorePrintf("attr/os/system32_dir", "%s", buf);
        strcat(buf, "\\hal.dll");
        versize = GetFileVersionInfoSize(buf, &tmp);
        if (versize == 0) {
            XenstorePrintf("attr/os/hal", "<unknown versize=0>");
            goto done_hal;
        }
        buffer = malloc(versize);
        if (!buffer) {
            XenstorePrintf("attr/os/hal", "<unknown versize=%d>", versize);
            goto done_hal;
        }
        if (GetFileVersionInfo(buf, tmp, versize, buffer) == 0) {
            PrintError("GetFileVersioInfo(hal.dll)");
            goto done_hal;
        }
        if (!VerQueryValue(buffer, TEXT("\\VarFileInfo\\Translation"),
                           (LPVOID *)&trans, &trans_size)) {
            PrintError("VerQueryValue(hal.Translation");
            goto done_hal;
        }
        if (trans_size < sizeof(*trans)) {
            XenstorePrintf("attr/os/hal", "<no translations>");
            goto done_hal;
        }
        sprintf(buffer2, "\\StringFileInfo\\%04x%04x\\InternalName",
                trans->language, trans->code_page);
        if (VerQueryValue(buffer, buffer2, (LPVOID *)&halname,
                          &halnamelen)) {
            XenstorePrintf("attr/os/hal", "%s", halname);

            if (!lstrcmpi(halname, "hal.dll")) {
                LegacyHal = TRUE;
            }
        } else {
            PrintError("VerQueryValue(hal.InternalName)");
        }
    done_hal:
        free(buffer);
    }

    /* Kernel command line */
    HKEY regKey;
    DWORD res;
    res = RegOpenKey(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control",
                     &regKey);
    if (res != ERROR_SUCCESS) {
        PrintError("RegOpenKey(\"HKLM\\SYSTEM\\CurrentControlSet\\Control\")");
    } else {
        DWORD keyType;
        DWORD tmp;
        tmp = sizeof(buf);
        res = RegQueryValueEx(regKey, "SystemStartOptions",
                              NULL, &keyType, (LPBYTE)buf, &tmp);
        if (res != ERROR_SUCCESS) {
            PrintError("RegQueryValue(SystemStartOptions)");
        } else if (keyType != REG_SZ) {
            XenstorePrintf("attr/os/boot_options", "<not string>");
        } else {
            XenstorePrintf("attr/os/boot_options", buf);
        }
        RegCloseKey(regKey);
        regKey = NULL;
    }

    AddHotFixInfoToStore(wmi);

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
EstablishWatch(const char *path)
{
    struct watch_event *we;
    DWORD err;

    we = (struct watch_event *)malloc(sizeof(*we));
    if (!we) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memset(we, 0, sizeof(*we));
    we->watch = NULL;
    we->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (we->event != INVALID_HANDLE_VALUE)
        we->watch = XenstoreWatch(path, we->event);
    if (we->watch == NULL) {
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
    void (*handler)(void *);
    void *ctx;
};

#define MAX_FEATURES 10
struct watch_feature_set {
    struct watch_feature features[MAX_FEATURES];
    unsigned nr_features;
};

static void
AddFeature(struct watch_feature_set *wfs, const char *path,
           const char *flag, const char *name,
           void (*handler)(void *), void *ctx)
{
    unsigned n;
    if (wfs->nr_features == MAX_FEATURES) {
        PrintError("Too many features!", ERROR_INVALID_FUNCTION);
        return;
    }
    n = wfs->nr_features;
    wfs->features[n].watch = EstablishWatch(path);
    if (wfs->features[n].watch == NULL) {
        PrintError("EstablishWatch() for AddFeature()");
        return;
    }
    wfs->features[n].feature_flag = flag;
    wfs->features[n].handler = handler;
    wfs->features[n].ctx = ctx;
    wfs->features[n].name = name;
    wfs->nr_features++;
}

static void
AdvertiseFeatures(struct watch_feature_set *wfs)
{
    unsigned x;
    for (x = 0; x < wfs->nr_features; x++) {
        if (wfs->features[x].feature_flag != NULL)
            XenstorePrintf(wfs->features[x].feature_flag, "1");
    }
}

int isBetterAgentInstalled() {
    LONG lRet = 0;
    DWORD betterAgent =0;
    HKEY hRegKey;



    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        XENTOOLS_INSTALL_REG_KEY, 
                        0, 
                        KEY_READ,
                        &hRegKey);

    if (lRet == ERROR_SUCCESS)
    {
        DWORD cbData;
        lRet = RegQueryValueEx(hRegKey, "MsiGuestAgent", NULL, NULL, (PBYTE)&betterAgent, &cbData);
        if (lRet != ERROR_SUCCESS) {
            betterAgent=0;
        }
    }
    else {
        betterAgent = 0;
        goto failKey;
    }
    RegCloseKey(hRegKey);
failKey:
    return betterAgent;
}

VOID
RegisterPVAddOns(
    WMIAccessor* wmi
    )
{
    HKEY hRegKey;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD dwVersion;
    DWORD cbData;

    // If we get here, the drivers are installed.
    XenstorePrintf ("attr/PVAddons/Installed", "1");

    // Put the major, minor, and build version numbers in the store.
    LONG lRet = 0;

    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        XENTOOLS_INSTALL_REG_KEY, 
                        0, 
                        KEY_READ,
                        &hRegKey);

    if (lRet == ERROR_SUCCESS)
    {
        cbData = sizeof(dwVersion);
#define DO_VERSION(type)                                                    \
        lRet = RegQueryValueEx (                                            \
            hRegKey,                                                        \
            #type "Version",                                                \
            NULL,                                                           \
            NULL,                                                           \
            (PBYTE)&dwVersion,                                              \
            &cbData);                                                       \
        if (lRet == ERROR_SUCCESS)                                          \
            XenstorePrintf ("attr/PVAddons/" #type "Version", "%d",         \
                            dwVersion);                                     \
        else                                                                \
            DBGPRINT (("Failed to get version " #type));
        DO_VERSION(Major);
        DO_VERSION(Minor);
        DO_VERSION(Micro);
        DO_VERSION(Build);
#undef DO_VERSION
        RegCloseKey(hRegKey);
    }

    AddSystemInfoToStore(wmi);
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

         /* Tell dom0 that we're no longer installed.  This is a bit
            of a hack. */
         InitXSAccessor();

         XenstorePrintf("attr/PVAddons/Installed", "0");
         XenstorePrintf("attr/PVAddons/MajorVersion", "0");
         XenstorePrintf("attr/PVAddons/MinorVersion", "0");
         XenstorePrintf("attr/PVAddons/BuildVersion", "0");

         /* Crank the update number so xapi notices it. */
         char *v;
         XenstoreRead("data/update_cnt", &v);
         if (v) {
             int cnt = atoi(v);
             XenstorePrintf("data/update_cnt", "%d", cnt + 1);
             XenstoreFree(v);
         }
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

static void maybeReboot(void *ctx)
{
	char *shutdown_type;
	unsigned int len;
	BOOL res;
	enum XShutdownType type;
    int cntr = 0;
    HANDLE eventLog;

	if (XenstoreRead("control/shutdown", &shutdown_type) < 0)
		return;
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
            if (!res)
                PrintError("ExitWindowsEx");
            else
                XenstoreRemove("control/shutdown");
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
            } else {
                XenstoreRemove("control/shutdown");
            }
        }
		break;
	case XShutdownSuspend:
        XenstorePrintf ("control/hibernation-state", "started");
        /* Even if we think hibernation is disabled, try it anyway.
           It's not like it can do any harm. */
		res = SetSystemPowerState(FALSE, FALSE);
        XenstoreRemove ("control/shutdown");
        if (!res) {
            /* Tell the tools that we've failed. */
            PrintError("SetSystemPowerState");
            XenstorePrintf ("control/hibernation-state", "failed");
        }
		break;
    case XShutdownS3:
        XenstorePrintf ("control/s3-state", "started");
        res = SetSuspendState(FALSE, TRUE, FALSE);
        XenstoreRemove ("control/shutdown");
        if (!res) {
            PrintError("SetSuspendState");
            XenstorePrintf ("control/s3-state", "failed");
        }
        break;
	}

out:
	XenstoreFree(shutdown_type);
}

static
void
GetWindowsVersion()
{
    OSVERSIONINFO info;
    info.dwOSVersionInfoSize = sizeof(info);

    WindowsVersion = 0;

    if (GetVersionEx(&info)) {
        if (((info.dwMajorVersion & ~0xff) == 0)
         && ((info.dwMinorVersion & ~0xff) == 0))
        {
            WindowsVersion = (info.dwMajorVersion << 8) |
                              info.dwMinorVersion;
        }
    }
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

static void
refreshStoreData(WMIAccessor *wmi, NicInfo *nicInfo,
                 TSInfo *tsInfo, struct watch_feature_set *wfs)
{
    PCHAR buffer = NULL;
    static int64_t last_meminfo_free;
    static int cntr;
    unsigned need_kick;

    need_kick = 0;
    if (XenstoreRead("attr/PVAddons/Installed",
                     &buffer) < 0) {
        if (GetLastError() == ERROR_NO_SYSTEM_RESOURCES)
            return;

        XsLogMsg("register ourself in the store");
        RegisterPVAddOns(wmi);
        nicInfo->Refresh();
        AdvertiseFeatures(wfs);
        need_kick = 1;
    } else {
        XenstoreFree(buffer);
    }

    if (XenstoreRead("data/meminfo_free", &buffer) < 0) {
        cntr = 0;
        last_meminfo_free = 0;
    } else {
        XenstoreFree(buffer);
    }

    if (XenstoreRead("data/ts", &buffer) < 0) {
        cntr = 0;
    } else {
        XenstoreFree(buffer);
    }

    /* XXX HACK: Restrict ourselves to only doing this once every two
     * minutes or so (we get called about every 4.5 seconds). */
    if (cntr++ % 26 == 0) {
        VMData data;
        BOOLEAN enabled;

        XsLogMsg("Get memory data");
        memset(&data, 0, sizeof(VMData));
        GetWMIData(wmi, data);

        if (data.meminfo_free - last_meminfo_free > 1024 ||
            data.meminfo_free - last_meminfo_free < -1024) {
            XsLogMsg("update memory data in store");
            XenstoreDoDump(&data);
            need_kick = 1;
            last_meminfo_free = data.meminfo_free;
        }

        XsLogMsg("Refresh terminal services status");
        tsInfo->Refresh();

        XsLogMsg("Get volume mapping data");
    }

    if (need_kick)
        XenstoreKickXapi();
}

static void
ProcessTsControl(void *ctx)
{
    TSInfo *tsInfo = (TSInfo *)ctx;

    tsInfo->ProcessControl();
}

static void
processPing(void *ctx)
{
    XenstoreRemove("control/ping");
}

static void
processExec(void *ctx)
{
    char *val;
    char *file;
    if (XenstoreRead("control/exec/command", &val) >=0) {
        if (strcmp(val, "Install")==0) {
            if (XenstoreRead("control/exec/file", &file) >=0) {
                _spawnlp(_P_NOWAIT, "msiexec.exe", "/qn", "/i", file, NULL);
                XenstoreFree(file);
            }
            XenstoreFree(val);
        }
    }
    XenstoreRemove("control/exec/command");

}

static void
processDumpLog(void *ctx)
{
    char *val;
    int do_it;

    do_it = 0;
    if (XenstoreRead("control/dumplog", &val) >= 0) {
        XenstoreFree(val);
        do_it = 1;
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND)
        do_it = 1;

    if (do_it) {
        XsDumpLogThisThread();
        XenstoreRemove("control/dumplog");
    }
}

//
// Main loop
//
void Run()
{
    VMData data;
    bool exit=false;
    PCHAR pPVAddonsInstalled = NULL;
    STARTUPINFO startInfo;
    PROCESS_INFORMATION processInfo;
    HANDLE suspendEvent;
    MSG msg;
    int cntr = 0;
    NicInfo *nicInfo;
    TSInfo *tsInfo;
    struct watch_feature_set features;
    BOOL snap = FALSE;

    XsLogMsg("Guest agent main loop starting");

    memset(&features, 0, sizeof(features));

    GetWindowsVersion();


    AddFeature(&features, "control/shutdown", "control/feature-shutdown", 
               "shutdown", maybeReboot, NULL);
    AddFeature(&features, "control/ping", NULL, "ping", processPing, NULL);
    AddFeature(&features, "control/exec/command", NULL, "Exec", processExec, NULL);
    AddFeature(&features, "control/dumplog", NULL, "dumplog", processDumpLog, NULL);

    suspendEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!suspendEvent) {
        PrintError("CreateEvent() suspendEvent");
    } else {
        if (ListenSuspend(suspendEvent) < 0) {
            PrintError("ListenSuspend()");
            CloseHandle(suspendEvent);
            suspendEvent = NULL;
        }
    }



    nicInfo = new NicInfo();
    nicInfo->Prime();

    tsInfo = new TSInfo();
    AddFeature(&features,
               "control/ts",
               "control/feature-ts",
               "ts",
               ProcessTsControl,
               tsInfo);

    XenstoreRemove("attr/PVAddons/Installed");
    refreshStoreData(wmi, nicInfo, tsInfo, &features);

    while (1)
    {
        DWORD status;
        int nr_handles = 2;
        HANDLE handles[3 + MAX_FEATURES];
        unsigned x;

        handles[0] = hServiceExitEvent;
        handles[1] = nicInfo->NicChangeEvent;
        if (suspendEvent)
            handles[nr_handles++] = suspendEvent;
        for (x = 0; x < features.nr_features; x++)
            handles[nr_handles++] = features.features[x].watch->event;

        XsLogMsg("win agent going to sleep");
        status = WaitForMultipleObjects(nr_handles, handles, FALSE, 4500);
        XsLogMsg("win agent woke up for %d", status);

        /* WAIT_OBJECT_0 happens to be 0, so the compiler gets shirty
           about status >= WAIT_OBJECT_0 (since status is unsigned).
           This is more obviously correct than the compiler-friendly
           version, though, so just disable the warning. */
        if (status == WAIT_TIMEOUT) {
            refreshStoreData(wmi, nicInfo, tsInfo, &features);
        }
#pragma warning (disable: 4296)
        else if (status >= WAIT_OBJECT_0 &&
                 status < WAIT_OBJECT_0 + nr_handles)
#pragma warning (default: 4296)
        {
            HANDLE event = handles[status - WAIT_OBJECT_0];
            if (event == hServiceExitEvent)
            {
                XsLogMsg("service exit event");
                break;
            }
            else if (event == nicInfo->NicChangeEvent)
            {
                XsLogMsg("NICs changed");
                nicInfo->Refresh();
                XenstoreKickXapi();
                XsLogMsg("Handled NIC change");
                nicInfo->Prime();
            }
            else if (event == suspendEvent)
            {
                XsLogMsg("Suspend event");
                finishSuspend();
                refreshStoreData(wmi, nicInfo, tsInfo, &features);
                XsLogMsg("Handled suspend event");
            }
            else
            {
                for (x = 0; x < features.nr_features; x++) {
                    if (features.features[x].watch->event == event) {
                        XsLogMsg("fire feature %s", features.features[x].name);
                        features.features[x].handler(features.features[x].ctx);
                        XsLogMsg("fired feature %s",
                                 features.features[x].name);
                    }
                }
            }
        }
        else
        {
            PrintError("WaitForMultipleObjects()");
            break;
        }
    }

    XsLogMsg("Guest agent finishing");
    ReleaseWMIAccessor(wmi);


    delete tsInfo;
    delete nicInfo;

    ServiceControlManagerUpdate(0, SERVICE_STOPPED);

    if (SLC_API != NULL)
        FreeLibrary(SLC_API);
    if (SLWGA_API != NULL)
        FreeLibrary(SLWGA_API);

    XsLogMsg("Guest agent finished");
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

    if (isBetterAgentInstalled()) {
	    ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
	    SetServiceStatus (hStatus, &ServiceStatus);
    }

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

    XsInitPerThreadLogging();

    ConnectToWMI();
    InitXSAccessor();
    XsLog("Guest agent service starting");

    __try
    {
        Run();
    }
    __except(XsDumpLogThisThread(), EXCEPTION_CONTINUE_SEARCH)
    {
    }

    XsLog("Guest agent service stopped");
    ShutdownXSAccessor();

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
