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

#if !defined(_XENIFACE_H_)
#define _XENIFACE_H_

#include <ntddk.h>

#include <wmilib.h>

#include <initguid.h> // required for GUID definitions

#pragma warning(disable:4100 4057)

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include "..\..\include\store_interface.h"
#include "..\..\include\shared_info_interface.h"
#include "..\..\include\suspend_interface.h"

#define XENIFACE_POOL_TAG (ULONG) 'XIfc'
#define XENIFACE_FDO_INSTANCE_SIGNATURE (ULONG) 'XenI'

#define XENIFACE_WAIT_WAKE_ENABLE L"WaitWakeEnabled"

#define XENIFACE_POWER_SAVE_ENABLE L"PowerSaveEnabled"

#if !defined(InterlockedOr) && (_WIN32_WINNT==0x0500)
#define InterlockedOr _InterlockedOr
#endif

#if !defined(EVENT_TRACING)
#define     ERROR    0
#define     WARNING  1
#define     TRACE    2
#define     INFO     3

VOID
XenIfaceDebugPrint    (
    __in ULONG   DebugPrintLevel,
    __in PCCHAR  DebugMessage,
    ...
    );

#else
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(XenIface,(C56386BD,7C67,4264,B8D9,C4A53B93CBEB), \
        WPP_DEFINE_BIT(ERROR)                /* bit  0 = 0x00000001 */ \
        WPP_DEFINE_BIT(WARNING)              /* bit  1 = 0x00000002 */ \
        WPP_DEFINE_BIT(TRACE)                /* bit  2 = 0x00000004 */ \
        WPP_DEFINE_BIT(INFO)                 /* bit  3 = 0x00000008 */ \
        WPP_DEFINE_BIT(DebugFlag04)          /* bit  4 = 0x00000010 */ \
        WPP_DEFINE_BIT(DebugFlag05)          /* bit  5 = 0x00000020 */ \
        WPP_DEFINE_BIT(DebugFlag06)          /* bit  6 = 0x00000040 */ \
        WPP_DEFINE_BIT(DebugFlag07)          /* bit  7 = 0x00000080 */ \
        WPP_DEFINE_BIT(DebugFlag08)          /* bit  8 = 0x00000100 */ \
        WPP_DEFINE_BIT(DebugFlag09)          /* bit  9 = 0x00000200 */ \
        WPP_DEFINE_BIT(DebugFlag10)          /* bit 10 = 0x00000400 */ \
        WPP_DEFINE_BIT(DebugFlag11)          /* bit 11 = 0x00000800 */ \
        WPP_DEFINE_BIT(DebugFlag12)          /* bit 12 = 0x00001000 */ \
        WPP_DEFINE_BIT(DebugFlag13)          /* bit 13 = 0x00002000 */ \
        WPP_DEFINE_BIT(DebugFlag14)          /* bit 14 = 0x00004000 */ \
        WPP_DEFINE_BIT(DebugFlag15)          /* bit 15 = 0x00008000 */ \
        WPP_DEFINE_BIT(DebugFlag16)          /* bit 16 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag17)          /* bit 17 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag18)          /* bit 18 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag19)          /* bit 19 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag20)          /* bit 20 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag21)          /* bit 21 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag22)          /* bit 22 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag23)          /* bit 23 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag24)          /* bit 24 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag25)          /* bit 25 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag26)          /* bit 26 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag27)          /* bit 27 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag28)          /* bit 28 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag29)          /* bit 29 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag30)          /* bit 30 = 0x00000000 */ \
        WPP_DEFINE_BIT(DebugFlag31)          /* bit 31 = 0x00000000 */ \
        )
#endif

typedef struct _GLOBALS {

    UNICODE_STRING RegistryPath;

} GLOBALS;

extern GLOBALS Globals;

#define XENIFACE_WMI_STD_I8042 0
#define XENIFACE_WMI_STD_SERIAL 1
#define XENIFACE_WMI_STD_PARALEL 2
#define XENIFACE_WMI_STD_USB 3

typedef struct _XENIFACE_WMI_STD_DATA {

    UINT32   ConnectorType;

    UINT32   Capacity;

    UINT32   ErrorCount;

    UINT32   Controls;

    UINT32  DebugPrintLevel;

} XENIFACE_WMI_STD_DATA, * PXENIFACE_WMI_STD_DATA;

typedef enum _DEVICE_PNP_STATE {

    NotStarted = 0,
    Started,
    StopPending,
    Stopped,
    RemovePending,
    SurpriseRemovePending,
    Deleted

} DEVICE_PNP_STATE;

#define INITIALIZE_PNP_STATE(_Data_)    \
        (_Data_)->DevicePnPState =  NotStarted;\
        (_Data_)->PreviousPnPState = NotStarted;

#define SET_NEW_PNP_STATE(_Data_, _state_) \
        (_Data_)->PreviousPnPState =  (_Data_)->DevicePnPState;\
        (_Data_)->DevicePnPState = (_state_);

#define RESTORE_PREVIOUS_PNP_STATE(_Data_)   \
        (_Data_)->DevicePnPState =   (_Data_)->PreviousPnPState;\

typedef enum _QUEUE_STATE {

    HoldRequests = 0,
    AllowRequests,
    FailRequests

} QUEUE_STATE;

typedef enum {

    WAKESTATE_DISARMED          = 1,
    WAKESTATE_WAITING           = 2,
    WAKESTATE_WAITING_CANCELLED = 3,
    WAKESTATE_ARMED             = 4,
    WAKESTATE_ARMING_CANCELLED  = 5,
    WAKESTATE_COMPLETING        = 7
} WAKESTATE;

typedef struct _FDO_DATA
{


    ULONG   Signature;

    PDEVICE_OBJECT      Self;

    PDEVICE_OBJECT      UnderlyingPDO;

    PDEVICE_OBJECT      NextLowerDriver;

    DEVICE_PNP_STATE    DevicePnPState;

    DEVICE_PNP_STATE    PreviousPnPState;

    UNICODE_STRING      InterfaceName;


    QUEUE_STATE         QueueState;

    LIST_ENTRY          NewRequestsQueue;

    KSPIN_LOCK          QueueLock;

    KEVENT              RemoveEvent;

    KEVENT              StopEvent;

    ULONG               OutstandingIO;



    BOOLEAN             DontDisplayInUI;

    SYSTEM_POWER_STATE  SystemPowerState;

    DEVICE_POWER_STATE  DevicePowerState;

    WMILIB_CONTEXT      WmiLibInfo;

    XENIFACE_WMI_STD_DATA   StdDeviceData;

    DEVICE_CAPABILITIES DeviceCaps;

    PIRP                PendingSIrp;

    BOOLEAN             AllowIdleDetectionRegistration;

    BOOLEAN             AllowWakeArming;


    WAKESTATE           WakeState;

    PIRP                WakeIrp;

    KEVENT              WakeCompletedEvent;

    KEVENT              WakeDisableEnableLock;

    UNICODE_STRING      SuggestedInstanceName;

    USHORT              Sessions;

    FAST_MUTEX          SessionLock;

    LIST_ENTRY          SessionHead;

    PXENBUS_SUSPEND_CALLBACK SuspendHandler;

#define MAX_SESSIONS    (65536)

    int                 WmiReady;

    PXENBUS_SUSPEND_INTERFACE  SuspendInterface;

    PXENBUS_STORE_INTERFACE  StoreInterface;

    PXENBUS_SHARED_INFO_INTERFACE SharedInfoInterface;

    BOOLEAN             InterfacesAcquired;

	PKTHREAD			registryThread;
	KEVENT				registryWriteEvent;
	KEVENT				registryThreadEndEvent;

}  FDO_DATA, *PFDO_DATA;

#define CLRMASK(x, mask)     ((x) &= ~(mask));
#define SETMASK(x, mask)     ((x) |=  (mask));


DRIVER_INITIALIZE DriverEntry;

DRIVER_ADD_DEVICE XenIfaceAddDevice;

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH XenIfaceDispatchPnp;

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH XenIfaceDispatchPower;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
__drv_dispatchType(IRP_MJ_READ)
__drv_dispatchType(IRP_MJ_WRITE)
DRIVER_DISPATCH XenIfaceDispatchIO;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH XenIfaceCreate;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH XenIfaceClose;

__drv_dispatchType(IRP_MJ_CLEANUP)
DRIVER_DISPATCH XenIfaceCleanup;

__drv_dispatchType(IRP_MJ_SYSTEM_CONTROL)
DRIVER_DISPATCH XenIfaceSystemControl;

DRIVER_DISPATCH XenIfaceDispatchIoctl;

DRIVER_DISPATCH XenIfaceReadWrite;

DRIVER_DISPATCH XenIfaceSendIrpSynchronously;

DRIVER_DISPATCH XenIfaceCanStopDevice;

DRIVER_DISPATCH XenIfaceCanRemoveDevice;

DRIVER_UNLOAD XenIfaceUnload;

DRIVER_CANCEL XenIfaceCancelQueued;

IO_COMPLETION_ROUTINE XenIfaceDispatchPnpComplete;

NTSTATUS
XenIfaceStartDevice (
    __in PFDO_DATA     FdoData,
    __in PIRP             Irp
    );

LONG
XenIfaceIoIncrement    (
    __in  PFDO_DATA   FdoData
    );

LONG
XenIfaceIoDecrement    (
    __in  PFDO_DATA   FdoData
    );

NTSTATUS
XenIfaceGetDeviceCapabilities(
    __in  PDEVICE_OBJECT          DeviceObject,
    __in  PDEVICE_CAPABILITIES    DeviceCapabilities
    );

NTSTATUS
XenIfaceSetWmiDataItem(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in ULONG GuidIndex,
    __in ULONG InstanceIndex,
    __in ULONG DataItemId,
    __in ULONG BufferSize,
    __in_bcount(BufferSize) PUCHAR Buffer
    );

NTSTATUS
XenIfaceSetWmiDataBlock(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in ULONG GuidIndex,
    __in ULONG InstanceIndex,
    __in ULONG BufferSize,
    __in_bcount(BufferSize) PUCHAR Buffer
    );

NTSTATUS
XenIfaceQueryWmiDataBlock(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in ULONG GuidIndex,
    __in ULONG InstanceIndex,
    __in ULONG InstanceCount,
    __inout PULONG InstanceLengthArray,
    __in ULONG BufferAvail,
    __out_bcount(BufferAvail) PUCHAR Buffer
    );

NTSTATUS
XenIfaceQueryWmiRegInfo(
    __in PDEVICE_OBJECT DeviceObject,
    __out ULONG *RegFlags,
    __out PUNICODE_STRING InstanceName,
    __out PUNICODE_STRING *RegistryPath,
    __out PUNICODE_STRING MofResourceName,
    __out PDEVICE_OBJECT *Pdo
    );

PCHAR
WMIMinorFunctionString (
    __in UCHAR MinorFunction
);

NTSTATUS
GetDeviceFriendlyName(
    __in PDEVICE_OBJECT Pdo,
    __inout PUNICODE_STRING DeviceName
    );

NTSTATUS
XenIfaceWmiRegistration(
    __in PFDO_DATA               FdoData
);

NTSTATUS
XenIfaceWmiDeRegistration(
    __in PFDO_DATA               FdoData
);

NTSTATUS
XenIfaceReturnResources (
    __in PDEVICE_OBJECT DeviceObject
    );

NTSTATUS
XenIfaceQueueRequest(
    __in PFDO_DATA FdoData,
    __in PIRP Irp
    );


VOID
XenIfaceProcessQueuedRequests(
    __in PFDO_DATA FdoData
    );

NTSTATUS
XenIfaceFunctionControl(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in ULONG GuidIndex,
    __in WMIENABLEDISABLECONTROL Function,
    __in BOOLEAN Enable
    );

NTSTATUS
XenIfaceDispatchWaitWake(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

NTSTATUS
XenIfaceSetWaitWakeEnableState(
    __in PFDO_DATA FdoData,
    __in BOOLEAN WakeState
    );

BOOLEAN
XenIfaceGetWaitWakeEnableState(
    __in PFDO_DATA   FdoData
    );

VOID
XenIfaceAdjustCapabilities(
    __in PDEVICE_CAPABILITIES DeviceCapabilities
    );

BOOLEAN
XenIfaceArmForWake(
    __in  PFDO_DATA   FdoData,
    __in  BOOLEAN     DeviceStateChange
    );

VOID
XenIfaceDisarmWake(
    __in  PFDO_DATA   FdoData,
    __in  BOOLEAN     DeviceStateChange
    );

NTSTATUS
XenIfaceWaitWakeIoCompletionRoutine(
    __in PDEVICE_OBJECT   DeviceObject,
    __in PIRP             Irp,
    __in PVOID            Context
    );

VOID
XenIfaceWaitWakePoCompletionRoutine(
    __in  PDEVICE_OBJECT      DeviceObject,
    __in  UCHAR               MinorFunction,
    __in  POWER_STATE         PowerState,
    __in  PVOID               PowerContext,
    __in  PIO_STATUS_BLOCK    IoStatus
    );

VOID
XenIfacePassiveLevelReArmCallbackWorker(
    __in PDEVICE_OBJECT DeviceObject,
    __in PVOID Context
    );

VOID
XenIfacePassiveLevelClearWaitWakeEnableState(
    __in PDEVICE_OBJECT DeviceObject,
    __in PVOID Context
    );

VOID
XenIfaceQueuePassiveLevelCallback(
    __in PFDO_DATA    FdoData,
    __in PIO_WORKITEM_ROUTINE CallbackFunction
    );

VOID
XenIfaceRegisterForIdleDetection(
    __in PFDO_DATA   FdoData,
    __in BOOLEAN      DeviceStateChange
    );

VOID
XenIfaceDeregisterIdleDetection(
    __in PFDO_DATA   FdoData,
    __in BOOLEAN      DeviceStateChange
    );

NTSTATUS
XenIfaceSetPowerSaveEnableState(
    __in PFDO_DATA FdoData,
    __in BOOLEAN State
    );

BOOLEAN
XenIfaceGetPowerSaveEnableState(
    __in PFDO_DATA   FdoData
    );

VOID
XenIfacePowerUpDevice(
    __in PFDO_DATA FdoData
    );

PCHAR
PnPMinorFunctionString (
    __in UCHAR MinorFunction
);

NTSTATUS
FdoQueryInterfaces(
    IN  FDO_DATA*         Fdo
    );
void
FdoReleaseInterfaces(
    IN FDO_DATA*         Fdo
    )
;

void
FdoInitialiseXSRegistryEntries(
    IN FDO_DATA*        Fdo
    )
;

void 
FireSuspendEvent(
        PFDO_DATA fdoData
);



void SessionsSuspendAll(FDO_DATA *fdoData);

void SessionsResumeAll(FDO_DATA *fdoData);
#endif  // _XENIFACE_H_


