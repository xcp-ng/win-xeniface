#ifndef _XENCONTROL_PRIVATE_H_
#define _XENCONTROL_PRIVATE_H_

#include <windows.h>
#include "xencontrol.h"

#define Log(level, format, ...) \
        _Log(Xc->Logger, level, Xc->LogLevel, __FUNCTION__, format, __VA_ARGS__)

typedef struct _XENCONTROL_CONTEXT {
    HANDLE XenIface;
    XENCONTROL_LOGGER *Logger;
    XENCONTROL_LOG_LEVEL LogLevel;
} XENCONTROL_CONTEXT, *PXENCONTROL_CONTEXT;

#endif // _XENCONTROL_PRIVATE_H_
