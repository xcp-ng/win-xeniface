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

#include "service.h"
#include "convdevice.h"
#include "devicelist.h"
#include "messages.h"

/* 317fc439-3f77-41c8-b09e-08ad63272aa3 */
DEFINE_GUID(GUID_GPIOBUTTONS_LAPTOPSLATE_INTERFACE, \
            0x317fc439, 0x3f77, 0x41c8, 0xb0, 0x9e, 0x08, 0xad, 0x63, 0x27, 0x2a, 0xa3);

CConvDevice::CConvDevice(const wchar_t* path) : CDevice(path)
{
}

/*virtual*/ CConvDevice::~CConvDevice()
{
}

void CConvDevice::SetMode(DWORD new_mode)
{
    DisablePrompt();

    CXenAgent::Log("New mode = %s\n", new_mode ? "Laptop" : "Slate");

    for (;;) {
        BYTE buffer(0);
        DWORD current_mode(CCONV_DEVICE_UNKNOWN_MODE);

        if (!GetMode(&current_mode))
            break;

        CXenAgent::Log("Current mode = %s\n",
                       current_mode ? "Laptop" : "Slate");

        if (current_mode == new_mode)
            break;

        if (Open()) {
            Write(&buffer, sizeof(buffer));
            Close();
        }

        Sleep(1000); // yield
    }
}

bool CConvDevice::DisablePrompt()
{
    HKEY key;
    LRESULT lr;
    std::string path;

    path = "System\\CurrentControlSet\\Control\\PriorityControl";

    lr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_ALL_ACCESS,
                      &key);
    if (lr != ERROR_SUCCESS)
        goto fail1;

    DWORD type(REG_DWORD);
    DWORD val(0);
    DWORD length;

    length = sizeof(val);
    lr = RegSetValueEx(key, "ConvertibleSlateModePromptPreference", NULL,
                       type, (LPBYTE)&val, length);
    if (lr != ERROR_SUCCESS)
        goto fail2;

    RegCloseKey(key);

    return true;

fail2:
    RegCloseKey(key);
fail1:
    return false;
}

bool CConvDevice::GetMode(DWORD *mode)
{
    HKEY key;
    LRESULT lr;
    std::string path;

    path = "System\\CurrentControlSet\\Control\\PriorityControl";

    lr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &key);
    if (lr != ERROR_SUCCESS)
        goto fail1;

    DWORD type;
    DWORD val;
    DWORD length;

    length = sizeof(val);
    lr = RegQueryValueEx(key, "ConvertibleSlateMode", NULL, &type,
                         (LPBYTE)&val, &length);
    if (lr != ERROR_SUCCESS || type != REG_DWORD)
        goto fail2;

    RegCloseKey(key);

    *mode = val;
    return true;

fail2:
    RegCloseKey(key);
fail1:
    return false;
}

CConvDeviceList::CConvDeviceList(CXenAgent* agent) : CDeviceList(GUID_GPIOBUTTONS_LAPTOPSLATE_INTERFACE), m_agent(agent)
{}

/*virtual*/ CConvDeviceList::~CConvDeviceList()
{}

/*virtual*/ CDevice* CConvDeviceList::Create(const wchar_t* path)
{
    return new CConvDevice(path);
}

/*virtual*/ void CConvDeviceList::OnDeviceAdded(CDevice* dev)
{
    UNREFERENCED_PARAMETER(dev);
}

/*virtual*/ void CConvDeviceList::OnDeviceRemoved(CDevice* dev)
{
    UNREFERENCED_PARAMETER(dev);
}

/*virtual*/ void CConvDeviceList::OnDeviceSuspend(CDevice* dev)
{
    UNREFERENCED_PARAMETER(dev);
}

/*virtual*/ void CConvDeviceList::OnDeviceResume(CDevice* dev)
{
    UNREFERENCED_PARAMETER(dev);
}

void CConvDeviceList::SetSlateMode(std::string& mode)
{
    CCritSec crit(&m_crit);
    CConvDevice* device = (CConvDevice*)GetFirstDevice();

    if (device == NULL)
        return;

    m_agent->EventLog(EVENT_XENUSER_MODE_SWITCH);

    if (mode == "laptop")
        device->SetMode(CCONV_DEVICE_LAPTOP_MODE);
    else if (mode == "slate")
        device->SetMode(CCONV_DEVICE_SLATE_MODE);
}
