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


#include <ntifs.h>
#include <initguid.h>
#include <wmistr.h>
#include <wmilib.h>
#include <stdio.h>
#include <guiddef.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include "wmi.h"
#include "driver.h"
#include "store_interface.h"
#include "suspend_interface.h"
#include "log.h"
#include "xeniface_ioctls.h"
#include <version.h>
#include "util.h"

#define WMI_POOL_TAG    'XenP'

#define UTF8MASK2 0x1FFF80
#define UTF8MASK3 0x1FF800
#define UTF8MASK4 0x1F0000

typedef enum _WMI_TYPE {
    WMI_DONE,
    WMI_STRING,
    WMI_BOOLEAN,
    WMI_SINT8,
    WMI_UINT8,
    WMI_SINT16,
    WMI_UINT16,
    WMI_INT32,
    WMI_UINT32,
    WMI_SINT64,
    WMI_UINT64,
    WMI_DATETIME,
    WMI_BUFFER,
    WMI_OFFSET,
    WMI_STRINGOFFSET
} WMI_TYPE;

#define MAX_WATCH_COUNT (MAXIMUM_WAIT_OBJECTS -1)

typedef struct _XENSTORE_SESSION {
    LIST_ENTRY                  ListEntry;
    LONG                        SessionId;
    UNICODE_STRING              StringId;
    UNICODE_STRING              InstanceName;
    PXENBUS_STORE_TRANSACTION   Transaction;
    LIST_ENTRY                  WatchList;
    int                         WatchCount;
    PKEVENT                     WatchEvents[MAXIMUM_WAIT_OBJECTS];
    KWAIT_BLOCK                 WatchWaitBlocks[MAXIMUM_WAIT_OBJECTS];
    KEVENT                      SessionChangedEvent;
    XENIFACE_MUTEX              WatchMapLock;
    BOOLEAN                     Changed;
    BOOLEAN                     Closing;
    BOOLEAN                     Suspended;
    PKTHREAD                    WatchThread;
} XENSTORE_SESSION, *PXENSTORE_SESSION;

typedef struct _XENSTORE_WATCH {
    LIST_ENTRY                  ListEntry;
    UNICODE_STRING              Path;
    PXENIFACE_FDO               Fdo;
    ULONG                       SuspendCount;
    BOOLEAN                     Finished;
    KEVENT                      WatchEvent;
    PXENBUS_STORE_WATCH         WatchHandle;
} XENSTORE_WATCH, *PXENSTORE_WATCH;

static FORCEINLINE PVOID
WmiAllocate(
    IN  ULONG   Length
    )
{
    // Zeroes the allocation
    return __AllocatePoolWithTag(NonPagedPool, Length, WMI_POOL_TAG);
}

static FORCEINLINE VOID
WmiFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, WMI_POOL_TAG);
}

// Rather inconveniently, xenstore needs UTF8 data, WMI works in UTF16
// and windows doesn't provide conversion functions in any version
// prior to Windows 7.
static USHORT
Utf32FromUtf16(
    OUT PULONG          utf32,
    IN  const WCHAR*    utf16
    )
{
    ULONG               w;
    ULONG               u;
    ULONG               xa;
    ULONG               xb;
    ULONG               x;

    if (((utf16[0]) & 0xFC00) == 0xD800) {
        w = ((utf16[0]) & 0X03FF) >> 6;
        u = w + 1;
        xa = utf16[0] & 0x3F;
        xb = utf16[1] & 0x03FF;
        x = (xa << 10) | xb;
        *utf32 = (u << 16) + x;
        return 2;
    } else {
        *utf32 = *utf16;
        return 1;
    }
}

static USHORT
Utf32FromUtf8(
    OUT PULONG      utf32,
    IN  const CHAR* utf8
    )
{
    ULONG           y;
    ULONG           x;
    ULONG           z;
    ULONG           ua;
    ULONG           ub;
    ULONG           u;

    if ((utf8[0] & 0x80) == 0) {
        *utf32 = utf8[0];
        return 1;
    } else if ((utf8[0] & 0xE0) == 0xC0) {
        y = utf8[0] & 0x1F;
        x = utf8[1] & 0x3F;
        *utf32 = (y << 6) | x;
        return 2;
    } else if ((utf8[0] & 0xF0) == 0xE0) {
        z = utf8[0] & 0x0F;
        y = utf8[1] & 0x3F;
        x = utf8[2] & 0x3F;
        *utf32 = (z << 12) | (y << 6) | x;
       return 3;
    } else {
        ua = utf8[0] & 0x7;
        ub = (utf8[1] & 0x30) >> 4;
        u = (ua << 2) | ub;
        z = utf8[1] & 0x0f;
        y = utf8[2] & 0x3f;
        x = utf8[3] & 0x3f;
        *utf32 = (u << 16) | (z << 12) | (y << 6) | x;
        return 4;
    }
}

static USHORT
Utf16FromUtf32(
    OUT PWCHAR  utf16,
    IN  ULONG   utf32
    )
{
    WCHAR       u;
    WCHAR       w;
    WCHAR       x;

    if ((utf32 > 0xFFFF)) {
        u = (utf32 & 0x1F0000) >> 16;
        w = u - 1;
        x = utf32 & 0xFFFF;
        utf16[0] = 0xD800 | (w << 6) | (x >> 10);
        utf16[1] = 0xDC00 | (x & 0x3F);
        return 2;
    } else {
        utf16[0] = utf32 & 0xFFFF;
        return 1;
    }
}

static USHORT
CountUtf8FromUtf32(
    IN  ULONG   utf32
    )
{
    if (utf32 & UTF8MASK4)
        return 4;
    if (utf32 & UTF8MASK3)
        return 3;
    if (utf32 & UTF8MASK2)
        return 2;
    return 1;
}

static USHORT
CountUtf16FromUtf32(
    IN  ULONG   utf32
    )
{
    if (utf32 & 0xFF0000)
        return 2;
    return 1;
}

static USHORT
Utf8FromUtf32(
    OUT PCHAR   dest,
    IN  ULONG   utf32
    )
{
    CHAR        u;
    CHAR        y;
    CHAR        x;
    CHAR        z;

    if (utf32 & UTF8MASK4) {
        x = utf32 & 0x3f;
        y = (utf32 >> 6) & 0x3f;
        z = (utf32 >> 12) & 0xf;
        u = (utf32 >> 16) & 0x1f;
        dest[0] = 0xf0 | u >> 2;
        dest[1] = 0x80 | (u & 0x3) << 4 | z;
        dest[2] = 0x80 | y;
        dest[3] = 0x80 | x;
        return 4;
    } else if (utf32 & UTF8MASK3) {
        x = utf32 & 0x3f;
        y = (utf32 >> 6) & 0x3f;
        z = (utf32 >> 12) & 0xf;
        dest[0] = 0xe0 | z;
        dest[1] = 0x80 | y;
        dest[2] = 0x80 | x;
        return 3;
    } else if (utf32 & UTF8MASK2) {
        x = utf32 & 0x3f;
        y = (utf32 >> 6) & 0x3f;
        dest[0] = 0xc0 | y;
        dest[1] = 0x80 | x;
        return 2;
    } else {
        x = utf32 & 0x7f;
        dest[0] = x;
        return 1;
    }
}

static USHORT
CountBytesUtf16FromUtf8String(
    IN  PCOEM_STRING        utf8
    )
{
    ULONG                   utf32;
    int                     i = 0;
    USHORT                  bytecount = 0;

    while (i < utf8->Length && utf8->Buffer[i] != 0) {
        i += Utf32FromUtf8(&utf32, &utf8->Buffer[i]);
        bytecount += CountUtf16FromUtf32(utf32);
    }

    return bytecount * sizeof(WCHAR);
}

static USHORT
CountBytesUtf16FromUtf8(
    IN  const CHAR*     utf8
    )
{
    ULONG               utf32;
    int                 i = 0;
    USHORT              bytecount = 0;

    while (utf8[i] !=0) {
        i += Utf32FromUtf8(&utf32, &utf8[i]);
        bytecount += CountUtf16FromUtf32(utf32);
    }

    return bytecount * sizeof(WCHAR);
}

static VOID
GetUnicodeString(
    OUT PUNICODE_STRING unicode,
    IN  USHORT          maxlength,
    IN  LPWSTR          location
    )
{
    USHORT              i;
    USHORT              length = 0;

    unicode->MaximumLength = maxlength;
    unicode->Buffer = location;
    // No appropriate function to determine the length of a possibly null
    // terminated string within a fixed sized buffer exists.
    for (i = 0; (i * sizeof(WCHAR)) < maxlength; i++) {
        if (location[i] != L'\0')
            length += sizeof(WCHAR);
        else
            break;
    }
    unicode->Length = length;
}

static NTSTATUS
GetAnsiString(
    OUT PANSI_STRING    ansi,
    IN  USHORT          maxlength,
    IN  LPWSTR          location
    )
{
    UNICODE_STRING      unicode;

    GetUnicodeString(&unicode, maxlength, location);
    return RtlUnicodeStringToAnsiString(ansi, &unicode, TRUE);
}

static NTSTATUS
GetUTF8String(
    OUT POEM_STRING     utf8,
    IN  USHORT          bufsize,
    IN  LPWSTR          ustring
    )
{
    ULONG               utf32;
    USHORT              bytecount = 0;
    USHORT              i = 0;

    while (i < bufsize / sizeof(WCHAR)) {
        i += Utf32FromUtf16(&utf32, &ustring[i]);
        bytecount += CountUtf8FromUtf32(utf32);
    }

    utf8->Length = 0;
    utf8->MaximumLength = 0;
    utf8->Buffer = WmiAllocate(bytecount + sizeof(WCHAR));
    if (utf8->Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    utf8->Length = bytecount;
    utf8->MaximumLength = bytecount + sizeof(WCHAR);

    bytecount = 0;
    i = 0;
    while (i < bufsize / sizeof(WCHAR)) {
        i += Utf32FromUtf16(&utf32, &ustring[i]);
        bytecount += Utf8FromUtf32(&(utf8->Buffer[bytecount]), utf32);
    }

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
FreeUTF8String(
    IN  POEM_STRING utf8
    )
{
    if (utf8->Buffer)
        WmiFree(utf8->Buffer);
    utf8->Buffer = NULL;
    utf8->Length = 0;
    utf8->MaximumLength = 0;
}

static NTSTATUS
GetCountedUTF8String(
    OUT POEM_STRING     utf8,
    IN  PUCHAR          location
    )
{
    USHORT bufsize = *(USHORT*)location;
    LPWSTR ustring = (LPWSTR)(location + sizeof(USHORT));
    return GetUTF8String(utf8, bufsize, ustring);
}

static VOID
GetCountedUnicodeString(
    OUT PUNICODE_STRING unicode,
    IN  PUCHAR          location
    )
{
    USHORT bufsize = *(USHORT*)location;
    LPWSTR ustring = (LPWSTR)(location + sizeof(USHORT));
    GetUnicodeString(unicode, bufsize, ustring);
}

static NTSTATUS
GetCountedAnsiString(
    OUT PANSI_STRING    ansi,
    IN  PUCHAR          location
    )
{
    USHORT bufsize = *(USHORT*)location;
    LPWSTR ustring = (LPWSTR)(location + sizeof(USHORT));
    return GetAnsiString(ansi, bufsize, ustring);
}

static FORCEINLINE size_t
GetCountedUtf8Size(
    IN  const CHAR* utf8
    )
{
    return sizeof(USHORT) + CountBytesUtf16FromUtf8(utf8);
}

static FORCEINLINE size_t
GetCountedUnicodeStringSize(
    IN  PCUNICODE_STRING    string
    )
{
    return sizeof(USHORT) + string->Length;
}

static VOID
WriteCountedUnicodeString(
    IN  PCUNICODE_STRING    ustr,
    IN  PUCHAR              location
    )
{
    *((USHORT*)location) = ustr->Length;
    RtlCopyMemory(location + sizeof(USHORT),
                  ustr->Buffer,
                  ustr->Length);
}

static NTSTATUS
WriteCountedUTF8String(
    IN  const CHAR*     string,
    IN  PUCHAR          location
    )
{
    UNICODE_STRING      unicode;
    USHORT              i;
    USHORT              b;
    USHORT              bytesize;
    ULONG               utf32;
    PWCHAR              buffer;

    bytesize = CountBytesUtf16FromUtf8(string);
    buffer = WmiAllocate(bytesize + sizeof(WCHAR));
    if (buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    i = 0;
    b = 0;
    while (string[i] != 0) {
        i += Utf32FromUtf8(&utf32, &string[i]);
        b += Utf16FromUtf32(&buffer[b], utf32);
    }

    RtlInitUnicodeString(&unicode, buffer);
    WriteCountedUnicodeString(&unicode, location);
    WmiFree(buffer);

    return STATUS_SUCCESS;
}

static VOID
AllocUnicodeStringBuffer(
    OUT PUNICODE_STRING string,
    IN  USHORT          buffersize
    )
{
    string->Length = 0;
    string->MaximumLength = 0;
    string->Buffer = WmiAllocate(buffersize);
    if (string->Buffer == NULL)
        return;

    string->MaximumLength = buffersize;
}

static FORCEINLINE VOID
FreeUnicodeStringBuffer(
    IN  PUNICODE_STRING string
    )
{
    if (string->Buffer)
        WmiFree(string->Buffer);
    string->Length = 0;
    string->MaximumLength = 0;
    string->Buffer = NULL;
}

static NTSTATUS
CloneUnicodeString(
    OUT PUNICODE_STRING     dest,
    IN  PCUNICODE_STRING    src
    )
{
    NTSTATUS                status;

    AllocUnicodeStringBuffer(dest, src->Length);
    if (dest->Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = RtlUnicodeStringCopy(dest, src);
    if (!NT_SUCCESS(status))
        FreeUnicodeStringBuffer(dest);

    return status;
}

static NTSTATUS
GetInstanceName(
    OUT PUNICODE_STRING dest,
    IN  PXENIFACE_FDO   Fdo,
    IN  const CHAR*     string
    )
{
    ANSI_STRING         ansi;
    UNICODE_STRING      unicode;
    NTSTATUS            status;
    size_t              destsz;

    RtlInitAnsiString(&ansi, string);
    status = RtlAnsiStringToUnicodeString(&unicode, &ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    destsz = Fdo->SuggestedInstanceName.Length +
             sizeof(WCHAR) +
             unicode.Length;

    status = STATUS_INSUFFICIENT_RESOURCES;
    AllocUnicodeStringBuffer(dest, (USHORT)destsz);
    if (dest->Buffer == NULL)
        goto fail2;

    status = RtlUnicodeStringPrintf(dest,
                                    L"%s\\%s",
                                    Fdo->SuggestedInstanceName.Buffer,
                                    unicode.Buffer);
    if (!NT_SUCCESS(status))
        goto fail3;

    RtlFreeUnicodeString(&unicode);
    return STATUS_SUCCESS;

fail3:
    FreeUnicodeStringBuffer(dest);

fail2:
    RtlFreeUnicodeString(&unicode);

fail1:
    return status;
}

static NTSTATUS
WriteInstanceName(
    IN  PXENIFACE_FDO   Fdo,
    IN  const CHAR*     string,
    IN  PUCHAR          location
    )
{
    UNICODE_STRING      destination;
    NTSTATUS            status;

    status = GetInstanceName(&destination, Fdo, string);
    if (!NT_SUCCESS(status))
        return status;

    WriteCountedUnicodeString(&destination, location);
    FreeUnicodeStringBuffer(&destination);
    return STATUS_SUCCESS;
}

static PSTR
Xmasprintf(
    IN  const char* fmt,
    ...
    )
{
    va_list         argv;
    PSTR            out;
    size_t          basesize = 128;
    size_t          unused;
    NTSTATUS        status;

    va_start(argv, fmt);
    do {
        basesize = basesize * 2;
        out =  WmiAllocate((ULONG)basesize);
        if (out == NULL)
            return NULL;

        status = RtlStringCbVPrintfExA(out, basesize, NULL, &unused, 0, fmt, argv);

        WmiFree(out);
    } while (status != STATUS_SUCCESS);

    out = WmiAllocate((ULONG)(basesize - unused + 1));
    if (out == NULL)
        return NULL;

    RtlStringCbVPrintfA(out, basesize - unused + 1, fmt, argv);

    va_end(argv);
    return out;
}

static FORCEINLINE VOID
UnicodeShallowCopy(
    IN  PUNICODE_STRING     dest,
    IN  PUNICODE_STRING     src
    )
{
    dest->Buffer = src->Buffer;
    dest->Length = src->Length;
    dest->MaximumLength = src->MaximumLength;
}

static FORCEINLINE int
CompareUnicodeStrings(
    IN  PCUNICODE_STRING    string1,
    IN  PCUNICODE_STRING    string2
    )
{
    if (string1->Length == string2->Length)
        return RtlCompareMemory(string1->Buffer,
                                string2->Buffer,
                                string1->Length) != string1->Length;
    return 1;
}

static int
AccessWmiBuffer(
    IN  PUCHAR  Buffer,
    IN  int     readbuffer,
    OUT ULONG*  RequiredSize,
    IN  size_t  BufferSize,
    ...
    )
{
    va_list     vl;
    ULONG_PTR   offset;
    ULONG_PTR   offby;
    PUCHAR      position = Buffer;
    PUCHAR      endbuffer = Buffer + BufferSize;
    int         overflow = 0;

    va_start(vl, BufferSize);
    for (;;) {
        WMI_TYPE type = va_arg(vl, WMI_TYPE);
        if (type == WMI_DONE)
            break;

#define WMITYPECASE(_wmitype, _type, _align)            \
        case _wmitype: {                                \
            _type** val;                                \
            offby = ((ULONG_PTR)position) % (_align);   \
            offset = ((_align) - offby) % (_align);     \
            position += offset;                         \
            if (position + sizeof(_type) > endbuffer)   \
                overflow = TRUE;                        \
            val = va_arg(vl, _type**);                  \
            *val = NULL;                                \
            if (!overflow)                              \
                *val = (_type *)position;               \
            position += sizeof(_type);                  \
        } break

        switch (type) {
        WMITYPECASE(WMI_BOOLEAN, UCHAR, 1);
        WMITYPECASE(WMI_SINT8, CHAR, 1);
        WMITYPECASE(WMI_UINT8, UCHAR, 1);
        WMITYPECASE(WMI_SINT16, SHORT, 2);
        WMITYPECASE(WMI_UINT16, USHORT, 2);
        WMITYPECASE(WMI_INT32, LONG, 4);
        WMITYPECASE(WMI_UINT32, ULONG, 4);
        WMITYPECASE(WMI_SINT64, LONGLONG, 8);
        WMITYPECASE(WMI_UINT64, ULONGLONG, 8);

        case WMI_STRING: {
            UCHAR** countstr;
            USHORT  strsize;
            offset = (2 - ((ULONG_PTR)position % 2)) % 2;
            position += offset;
            if (position + sizeof(USHORT) > endbuffer)
                overflow = TRUE;
            if (readbuffer) {
                if (!overflow)
                    strsize = *(USHORT*)position;
                else
                    strsize = 0;
                strsize += sizeof(USHORT);
            } else {
                strsize = va_arg(vl, USHORT);
            }
            if (position + strsize > endbuffer)
                overflow = TRUE;
            countstr = va_arg(vl, UCHAR**);
            *countstr = NULL;
            if (!overflow)
                *countstr = position;
            position += strsize;
        } break;

        case WMI_BUFFER: {
            ULONG   size = va_arg(vl, ULONG);
            UCHAR** buffer;
            if (position + size > endbuffer)
                overflow = TRUE;
            buffer = va_arg(vl, UCHAR**);
            *buffer = NULL;
            if (!overflow)
                *buffer = position;
            position += size;
        } break;

        case WMI_OFFSET: {
            ULONG   inpos = va_arg(vl, ULONG);
            UCHAR*  bufferpos = Buffer + inpos;
            ULONG   insize = va_arg(vl, ULONG);
            UCHAR** writebuf = va_arg(vl, UCHAR**);
            *writebuf = NULL;
            if (bufferpos + insize > endbuffer)
                overflow = TRUE;
            else
                *writebuf = bufferpos;
            // Only update position if it extends
            // the required size of the buffer
            if (bufferpos + insize > position)
                position = bufferpos + insize;
        } break;

        case WMI_STRINGOFFSET: {
            UCHAR** countstr;
            USHORT  strsize;
            ULONG   inpos = va_arg(vl, ULONG);
            UCHAR*  bufferpos = Buffer + inpos;
            if (bufferpos + sizeof(USHORT) > endbuffer)
                overflow = TRUE;
            if (readbuffer) {
                if (!overflow)
                    strsize = *(USHORT*)bufferpos;
                else
                    strsize = 0;
                strsize += sizeof(USHORT);
            } else {
                strsize = va_arg(vl, USHORT);
            }
            if (bufferpos + strsize > endbuffer)
                overflow = TRUE;
            countstr = va_arg(vl, UCHAR**);
            *countstr = NULL;
            if (!overflow)
                *countstr = bufferpos;
            if (bufferpos + strsize > position)
                position = bufferpos + strsize;
        } break;

        case WMI_DATETIME: {
            LPWSTR* val;
            offset = (2 - ((ULONG_PTR)position % 2)) % 2;
            position += offset;
            if (position + sizeof(WCHAR) * 25 > endbuffer)
                overflow = TRUE;
            val = va_arg(vl, LPWSTR*);
            *val = NULL;
            if (!overflow)
                *val = (LPWSTR)position;
            position += sizeof(WCHAR) * 25;
        } break;

        default:
            return FALSE;
        }
    }

    *RequiredSize = (ULONG)(position - Buffer);
    va_end(vl);
    if (overflow)
        return FALSE;
    return TRUE;
}

static FORCEINLINE PXENSTORE_SESSION
FindSessionLocked(
    IN  PXENIFACE_FDO   Fdo,
    IN  LONG            Id
    )
{
    PLIST_ENTRY         ListEntry;
    PXENSTORE_SESSION   Session;

    ASSERT3P(Fdo->SessionLock.Owner, ==, KeGetCurrentThread());

    for (ListEntry = Fdo->SessionHead.Flink;
         ListEntry != &Fdo->SessionHead;
         ListEntry = ListEntry->Flink) {
        Session = CONTAINING_RECORD(ListEntry, XENSTORE_SESSION, ListEntry);

        if (Session->SessionId != Id)
            continue;

        return Session->Suspended ? NULL : Session;
    }
    return NULL;
}

static FORCEINLINE PXENSTORE_WATCH
SessionFindWatchLocked(
    IN  PXENSTORE_SESSION   Session,
    IN  PUNICODE_STRING     Path
    )
{
    PLIST_ENTRY             ListEntry;
    PXENSTORE_WATCH         Watch;

    ASSERT3P(Session->WatchMapLock.Owner, ==, KeGetCurrentThread());

    for (ListEntry = Session->WatchList.Flink;
         ListEntry != &Session->WatchList;
         ListEntry = ListEntry->Flink) {
        Watch = CONTAINING_RECORD(ListEntry, XENSTORE_WATCH, ListEntry);

        if (CompareUnicodeStrings(Path, &Watch->Path) == 0)
            return Watch;
    }
    return NULL;
}

static VOID
FireWatch(
    IN  PXENSTORE_WATCH Watch
    )
{
    UCHAR*              eventdata;
    ULONG               RequiredSize;
    UCHAR*              sesbuf;

    (VOID) AccessWmiBuffer(NULL, FALSE, &RequiredSize, 0,
            WMI_STRING, GetCountedUnicodeStringSize(&Watch->Path), &sesbuf,
            WMI_DONE);

    eventdata = WmiAllocate(RequiredSize);
    if (eventdata == NULL)
        return;

    (VOID) AccessWmiBuffer(eventdata, FALSE, &RequiredSize, RequiredSize,
            WMI_STRING, GetCountedUnicodeStringSize(&Watch->Path), &sesbuf,
            WMI_DONE);

    WriteCountedUnicodeString(&Watch->Path, sesbuf);

    Trace("Fire Watch Event\n");
    WmiFireEvent(Watch->Fdo->Dx->DeviceObject,
                 (LPGUID)&OBJECT_GUID(XenStoreWatchEvent),
                 0,
                 RequiredSize,
                 eventdata);
}

KSTART_ROUTINE WatchCallbackThread;

static NTSTATUS
StartWatch(
    IN  PXENIFACE_FDO   Fdo,
    IN  PXENSTORE_WATCH Watch
    )
{
    char*               tmppath;
    ANSI_STRING         ansipath;
    NTSTATUS            status;

    status = RtlUnicodeStringToAnsiString(&ansipath, &Watch->Path, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    tmppath = WmiAllocate(ansipath.Length + 1);
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (tmppath == NULL)
        goto fail2;

    RtlCopyBytes(tmppath, ansipath.Buffer, ansipath.Length);

    status = XENBUS_STORE(WatchAdd,
                          &Fdo->StoreInterface,
                          NULL,
                          tmppath,
                          &Watch->WatchEvent,
                          &Watch->WatchHandle);
    if (!NT_SUCCESS(status))
        goto fail3;

    Info("Start Watch %p\n", Watch->WatchHandle);

    WmiFree(tmppath);
    RtlFreeAnsiString(&ansipath);

    return STATUS_SUCCESS;

fail3:
    WmiFree(tmppath);
fail2:
    RtlFreeAnsiString(&ansipath);
fail1:
    return status;
}

VOID
WatchCallbackThread(
    __in PVOID          StartContext
    )
{
    NTSTATUS            status;
    PLIST_ENTRY         ListEntry;
    PXENSTORE_WATCH     Watch;
    PXENSTORE_SESSION   Session = (PXENSTORE_SESSION)StartContext;
    int                 Count = 0;

    for (;;) {
        AcquireMutex(&Session->WatchMapLock);
        if (Session->Changed) {
            // Construct a new mapping
            Trace("Construct a new mapping\n");
            for (Count = 0, ListEntry = Session->WatchList.Flink;
                 ListEntry != &Session->WatchList;
                 Count++, ListEntry = ListEntry->Flink) {
                Watch = CONTAINING_RECORD(ListEntry, XENSTORE_WATCH, ListEntry);

                Session->WatchEvents[Count] = &Watch->WatchEvent;
            }
            Session->WatchEvents[Count] = &Session->SessionChangedEvent;
            Session->Changed = FALSE;
        }
        ReleaseMutex(&Session->WatchMapLock);

        Trace("Wait for new event\n");
        status = KeWaitForMultipleObjects(Count + 1,
                                          Session->WatchEvents,
                                          WaitAny,
                                          Executive,
                                          KernelMode,
                                          TRUE,
                                          NULL,
                                          Session->WatchWaitBlocks);
        Trace("got new event\n");

        if ((status >= STATUS_WAIT_0) && (status < STATUS_WAIT_0 + Count)) {
            Trace("watch or suspend\n");
            Watch = CONTAINING_RECORD(Session->WatchEvents[status - STATUS_WAIT_0],
                                      XENSTORE_WATCH,
                                      WatchEvent);

            AcquireMutex(&Session->WatchMapLock);
            KeClearEvent(&Watch->WatchEvent);

            if (Watch->Finished) {
                FreeUnicodeStringBuffer(&Watch->Path);
                RemoveEntryList(&Watch->ListEntry);
                WmiFree(Watch);

                Session->Changed = TRUE;
                Session->WatchCount--;
            } else if (!Session->Suspended &&
                       Watch->SuspendCount != XENBUS_SUSPEND(GetCount, &Watch->Fdo->SuspendInterface)) {
                Watch->SuspendCount = XENBUS_SUSPEND(GetCount, &Watch->Fdo->SuspendInterface);
                Info("SessionSuspendResumeUnwatch %p\n", Watch->WatchHandle);

                XENBUS_STORE(WatchRemove, &Watch->Fdo->StoreInterface, Watch->WatchHandle);
                Watch->WatchHandle = NULL;
                StartWatch(Watch->Fdo, Watch);
            } else {
                FireWatch(Watch);
            }

            ReleaseMutex(&Session->WatchMapLock);
        } else if (status == STATUS_WAIT_0 + Count) {
            AcquireMutex(&Session->WatchMapLock);
            KeClearEvent(&Session->SessionChangedEvent);
            if (Session->Closing) {
                Trace("Trying to end session thread\n");
                while (!IsListEmpty(&Session->WatchList)) {
                    ListEntry = RemoveHeadList(&Session->WatchList);
                    ASSERT(ListEntry != &Session->WatchList);

                    Session->WatchCount--;
                    Session->Changed = TRUE;

                    Watch = CONTAINING_RECORD(ListEntry, XENSTORE_WATCH, ListEntry);

                    FreeUnicodeStringBuffer(&Watch->Path);
                    WmiFree(Watch);
                }
                ReleaseMutex(&Session->WatchMapLock);

                Trace("Ending session thread\n");
                PsTerminateSystemThread(STATUS_SUCCESS);
            } else {
                ReleaseMutex(&Session->WatchMapLock);
            }
        }
    }
}

static NTSTATUS
SessionAddWatchLocked(
    IN  PXENIFACE_FDO       Fdo,
    IN  PXENSTORE_SESSION   Session,
    IN  PUNICODE_STRING     Path
    )
{
    PXENSTORE_WATCH         Watch;
    NTSTATUS                status;

    ASSERT3P(Session->WatchMapLock.Owner, ==, KeGetCurrentThread());

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Session->WatchCount >= MAX_WATCH_COUNT)
        goto fail1;

    Watch = WmiAllocate(sizeof(XENSTORE_WATCH));
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Watch == NULL)
        goto fail2;

    Watch->Finished = FALSE;
    Watch->Fdo = Fdo;
    Watch->SuspendCount = XENBUS_SUSPEND(GetCount, &Fdo->SuspendInterface);

    UnicodeShallowCopy(&Watch->Path, Path);
    KeInitializeEvent(&Watch->WatchEvent, NotificationEvent, FALSE);

    status = StartWatch(Fdo, Watch);
    if (!NT_SUCCESS(status))
        goto fail3;

    ASSERT(Watch->WatchHandle != NULL);

    Session->WatchCount++;
    InsertHeadList(&Session->WatchList, &Watch->ListEntry);

    Session->Changed = TRUE;
    KeSetEvent(&Session->SessionChangedEvent, IO_NO_INCREMENT,FALSE);

    return STATUS_SUCCESS;

fail3:
    WmiFree(Watch);
fail2:
fail1:
    return status;
}

static VOID
SessionRemoveWatchLocked(
    IN  PXENSTORE_WATCH     Watch
    )
{
    // ASSERT3P(Session->WatchMapLock.Owner, ==, KeGetCurrentThread());

    if (Watch->WatchHandle)
        XENBUS_STORE(WatchRemove, &Watch->Fdo->StoreInterface, Watch->WatchHandle);
    Watch->WatchHandle = NULL;

    Watch->Finished = TRUE;

    KeSetEvent(&Watch->WatchEvent, IO_NO_INCREMENT,FALSE);
}

static PXENSTORE_SESSION
FindSessionByInstanceLocked(
    IN  PXENIFACE_FDO       Fdo,
    IN  PUNICODE_STRING     Instance
    )
{
    PLIST_ENTRY             ListEntry;
    PXENSTORE_SESSION       Session;

    ASSERT3P(Fdo->SessionLock.Owner, ==, KeGetCurrentThread());

    for (ListEntry = Fdo->SessionHead.Flink;
         ListEntry != &Fdo->SessionHead;
         ListEntry = ListEntry->Flink) {
        Session = CONTAINING_RECORD(ListEntry, XENSTORE_SESSION, ListEntry);

        if (CompareUnicodeStrings(Instance, &Session->InstanceName) != 0)
            continue;

        return Session->Suspended ? NULL : Session;
    }
    return NULL;
}

__checkReturn
__success(return != NULL)
static PXENSTORE_SESSION
FindSessionByInstanceAndLock(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING Instance
    )
{
    PXENSTORE_SESSION   Session;

    AcquireMutex(&Fdo->SessionLock);
    Session = FindSessionByInstanceLocked(Fdo, Instance);
    if (Session == NULL)
         ReleaseMutex(&Fdo->SessionLock);
    return Session;
}

static NTSTATUS
SessionCreate(
    IN  PXENIFACE_FDO       Fdo,
    IN  PUNICODE_STRING     StringId,
    OUT ULONG*              SessionId
    )
{
    PXENSTORE_SESSION       Session;
    PSTR                    iname;
    NTSTATUS                status;
    ANSI_STRING             ansi;
    HANDLE                  hthread;
    OBJECT_ATTRIBUTES       oa;
    int                     count = 0;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Fdo->Sessions == MAX_SESSIONS)
        goto fail1;

    Session = WmiAllocate(sizeof(XENSTORE_SESSION));
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Session == NULL)
        goto fail2;

    status = RtlUnicodeStringToAnsiString(&ansi, StringId, TRUE);
    if (!NT_SUCCESS(status))
        goto fail3;

    InitializeMutex(&Session->WatchMapLock);
    Session->Changed = TRUE;

    AcquireMutex(&Fdo->SessionLock);
    do {
        FreeUnicodeStringBuffer(&Session->InstanceName);
        iname = Xmasprintf("Session_%s_%d", ansi.Buffer, count);

        status = STATUS_NO_MEMORY;
        if (iname == NULL)
            goto fail4;

        status = GetInstanceName(&Session->InstanceName, Fdo, iname);
        WmiFree(iname);
        if (!NT_SUCCESS(status))
            goto fail5;

        count++;
    } while (FindSessionByInstanceLocked(Fdo, &Session->InstanceName) != NULL);

    if (IsListEmpty(&Fdo->SessionHead)) {
        Session->SessionId = 0;
    } else {
        Session->SessionId = ((PXENSTORE_SESSION)(Fdo->SessionHead.Flink))->SessionId + 1;
        while (FindSessionLocked(Fdo, Session->SessionId))
            Session->SessionId = (Session->SessionId + 1) % MAX_SESSIONS;
    }

    Session->Closing = FALSE;
    Session->Transaction = NULL;

    *SessionId = Session->SessionId;

    UnicodeShallowCopy(&Session->StringId, StringId);
    InitializeListHead(&Session->WatchList);
    KeInitializeEvent(&Session->SessionChangedEvent, NotificationEvent, FALSE);

    if (Fdo->InterfacesAcquired){
        Trace("Add session unsuspended\n");
        Session->Suspended = FALSE;
    } else {
        Trace("Add session suspended\n");
        Session->Suspended = TRUE;
    }

    InsertHeadList(&Fdo->SessionHead, &Session->ListEntry);
    Fdo->Sessions++;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(&hthread, THREAD_ALL_ACCESS, &oa, NULL, NULL, WatchCallbackThread, Session);
    if (!NT_SUCCESS(status))
        goto fail6;

    ObReferenceObjectByHandle(hthread, THREAD_ALL_ACCESS, NULL, KernelMode,  &Session->WatchThread, NULL);
    ReleaseMutex(&Fdo->SessionLock);

    RtlFreeAnsiString(&ansi);

    return STATUS_SUCCESS;

fail6:
    RemoveEntryList(&Session->ListEntry);
    Fdo->Sessions--;
fail5:
fail4:
    ReleaseMutex(&Fdo->SessionLock);
    RtlFreeAnsiString(&ansi);
fail3:
    WmiFree(Session);
fail2:
fail1:
    return status;
}

static VOID
SessionRemoveLocked(
    IN  PXENIFACE_FDO       Fdo,
    IN  PXENSTORE_SESSION   Session
    )
{
    PLIST_ENTRY             ListEntry;
    PXENSTORE_WATCH         Watch;

    ASSERT3P(Fdo->SessionLock.Owner, ==, KeGetCurrentThread());

    RemoveEntryList(&Session->ListEntry);
    Fdo->Sessions--;

    AcquireMutex(&Session->WatchMapLock);
    for (ListEntry = Session->WatchList.Flink;
         ListEntry != &Session->WatchList;
         ListEntry = ListEntry->Flink) {
        Watch = CONTAINING_RECORD(ListEntry, XENSTORE_WATCH, ListEntry);

        SessionRemoveWatchLocked(Watch);
    }
    ReleaseMutex(&Session->WatchMapLock);

    if (Session->Transaction != NULL)
        XENBUS_STORE(TransactionEnd, &Fdo->StoreInterface, Session->Transaction, FALSE);
    Session->Transaction = NULL;

    Session->Closing = TRUE;

    KeSetEvent(&Session->SessionChangedEvent, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(Session->WatchThread, Executive, KernelMode, FALSE, NULL);

    ObDereferenceObject(Session->WatchThread);
    FreeUnicodeStringBuffer(&Session->StringId);
    FreeUnicodeStringBuffer(&Session->InstanceName);
    WmiFree(Session);
}

static VOID
SessionsRemoveAll(
    IN  PXENIFACE_FDO   Fdo
    )
{
    PXENSTORE_SESSION   Session;

    AcquireMutex(&Fdo->SessionLock);
    while (!IsListEmpty(&Fdo->SessionHead)) {
        ASSERT(Fdo->SessionHead.Flink != &Fdo->SessionHead);

        Session = CONTAINING_RECORD(Fdo->SessionHead.Flink,
                                    XENSTORE_SESSION,
                                    ListEntry);

        SessionRemoveLocked(Fdo, Session);
    }
    ReleaseMutex(&Fdo->SessionLock);
}

static VOID
SessionsSuspendLocked(
    IN  PXENIFACE_FDO       Fdo,
    IN  PXENSTORE_SESSION   Session
    )
{
    PLIST_ENTRY             ListEntry;
    PXENSTORE_WATCH         Watch;

    ASSERT3P(Fdo->SessionLock.Owner, ==, KeGetCurrentThread());

    AcquireMutex(&Session->WatchMapLock);
    for (ListEntry = Session->WatchList.Flink;
         ListEntry != &Session->WatchList;
         ListEntry = ListEntry->Flink) {
        Watch = CONTAINING_RECORD(ListEntry, XENSTORE_WATCH, ListEntry);

        if (Watch->WatchHandle != NULL)
            XENBUS_STORE(WatchRemove, &Watch->Fdo->StoreInterface, Watch->WatchHandle);
        Watch->WatchHandle = NULL;
    }
    Session->Suspended = TRUE;
    ReleaseMutex(&Session->WatchMapLock);

    if (Session->Transaction != NULL)
        XENBUS_STORE(TransactionEnd, &Fdo->StoreInterface, Session->Transaction, FALSE);
    Session->Transaction = NULL;
}

static VOID
SessionResumeLocked(
    IN  PXENSTORE_SESSION   Session
    )
{
    PLIST_ENTRY             ListEntry;
    PXENSTORE_WATCH         Watch;

    // ASSERT3P(Fdo->SessionLock.Owner, ==, KeGetCurrentThread());

    AcquireMutex(&Session->WatchMapLock);
    for (ListEntry = Session->WatchList.Flink;
         ListEntry != &Session->WatchList;
         ListEntry = ListEntry->Flink) {
        Watch = CONTAINING_RECORD(ListEntry, XENSTORE_WATCH, ListEntry);

        if (Watch->Finished)
            continue;

        Watch->SuspendCount = XENBUS_SUSPEND(GetCount, &Watch->Fdo->SuspendInterface);
        StartWatch(Watch->Fdo, Watch);
    }
    Session->Suspended = FALSE;

    Session->Changed = TRUE;
    KeSetEvent(&Session->SessionChangedEvent, IO_NO_INCREMENT,FALSE);
    ReleaseMutex(&Session->WatchMapLock);
}

static NTSTATUS
NodeTooSmall(
    IN  UCHAR*      Buffer,
    IN  ULONG       BufferSize,
    IN  ULONG       Needed,
    OUT ULONG_PTR*  BytesWritten
    )
{
    WNODE_TOO_SMALL*    node;
    ULONG               RequiredSize;

    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_TOO_SMALL), &node,
                         WMI_DONE)) {
        *BytesWritten = RequiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    node->WnodeHeader.BufferSize = sizeof(WNODE_TOO_SMALL);
    KeQuerySystemTime(&node->WnodeHeader.TimeStamp);
    node->WnodeHeader.Flags = WNODE_FLAG_TOO_SMALL;
    node->SizeNeeded = Needed;

    *BytesWritten = sizeof(WNODE_TOO_SMALL);
    return STATUS_SUCCESS;
}

static NTSTATUS
SessionExecuteRemoveValue(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    ULONG               RequiredSize;
    NTSTATUS            status;
    UCHAR*              upathname;
    OEM_STRING          pathname;
    PXENSTORE_SESSION   session;
    char*               tmpbuffer;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &upathname,
                         WMI_DONE))
        goto fail1;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail2;

    status = GetCountedUTF8String(&pathname, upathname);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmpbuffer = WmiAllocate(pathname.Length + 1);
    if (tmpbuffer == NULL)
        goto fail4;

    RtlCopyBytes(tmpbuffer, pathname.Buffer, pathname.Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceAndLock(Fdo, instance);
    if (session == NULL)
        goto fail5;

    status = XENBUS_STORE(Remove, &Fdo->StoreInterface, session->Transaction, NULL, tmpbuffer);
    ReleaseMutex(&Fdo->SessionLock);

    if (!NT_SUCCESS(status))
        goto fail6;

    WmiFree(tmpbuffer);
    FreeUTF8String(&pathname);

    return STATUS_SUCCESS;

fail6:
fail5:
    WmiFree(tmpbuffer);
fail4:
    FreeUTF8String(&pathname);
fail3:
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteRemoveWatch(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    NTSTATUS            status;
    ULONG               RequiredSize;
    UCHAR*              upathname;
    PXENSTORE_WATCH     watch;
    UNICODE_STRING      unicpath_notbacked;
    PXENSTORE_SESSION   session;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &upathname,
                         WMI_DONE))
        goto fail1;

    GetCountedUnicodeString(&unicpath_notbacked, upathname);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceAndLock(Fdo, instance);
    if (session == NULL)
        goto fail2;

    AcquireMutex(&session->WatchMapLock);
    watch = SessionFindWatchLocked(session, &unicpath_notbacked);
    if (watch) {
        SessionRemoveWatchLocked(watch);
    } else {
        Warning("No Watch\n");
    }
    ReleaseMutex(&session->WatchMapLock);

    ReleaseMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;

fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteSetWatch(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    ULONG               RequiredSize;
    NTSTATUS            status;
    UCHAR*              upathname;
    PXENSTORE_SESSION   Session;
    UNICODE_STRING      unicpath_notbacked;
    UNICODE_STRING      unicpath_backed;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &upathname,
                         WMI_DONE))
        goto fail1;

    GetCountedUnicodeString(&unicpath_notbacked, upathname);

    status = CloneUnicodeString(&unicpath_backed, &unicpath_notbacked);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    Session = FindSessionByInstanceAndLock(Fdo, instance);
    if (Session == NULL)
        goto fail3;

    AcquireMutex(&Session->WatchMapLock);

    status = SessionAddWatchLocked(Fdo, Session, &unicpath_backed);

    ReleaseMutex(&Session->WatchMapLock);

    ReleaseMutex(&Fdo->SessionLock);
    if (!NT_SUCCESS(status))
        goto fail4;

    return STATUS_SUCCESS;

fail4:
fail3:
    FreeUnicodeStringBuffer(&unicpath_backed);
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteEndSession(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    PXENSTORE_SESSION   Session;
    NTSTATUS            status;

    *BytesWritten = 0;
    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    Session = FindSessionByInstanceAndLock(Fdo, instance);
    if (Session == NULL)
        goto fail1;

    SessionRemoveLocked(Fdo, Session);
    ReleaseMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;

fail1:
    return status;
}

static NTSTATUS
SessionExecuteSetValue(
    IN  PXENIFACE_FDO       Fdo,
    IN  PUNICODE_STRING     instance,
    IN  UCHAR*              InBuffer,
    IN  ULONG               InBufferSize,
    IN  UCHAR*              OutBuffer,
    IN  ULONG               OutBufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    ULONG                   RequiredSize;
    NTSTATUS                status;
    UCHAR*                  upathname;
    UCHAR*                  uvalue;
    OEM_STRING              pathname;
    OEM_STRING              value;
    PXENSTORE_SESSION       session;
    char*                   tmppath;
    char*                   tmpvalue;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &upathname,
                         WMI_STRING, &uvalue,
                         WMI_DONE))
        goto fail1;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail2;

    status = GetCountedUTF8String(&pathname, upathname);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = WmiAllocate(pathname.Length + 1);
    if (tmppath == NULL)
        goto fail4;

    RtlCopyBytes(tmppath, pathname.Buffer, pathname.Length);

    status = GetCountedUTF8String(&value, uvalue);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmpvalue = WmiAllocate(value.Length + 1);
    if (tmpvalue == NULL)
        goto fail6;

    RtlCopyBytes(tmpvalue, value.Buffer, value.Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceAndLock(Fdo, instance);
    if (session == NULL)
        goto fail7;

    status = XENBUS_STORE(Printf, &Fdo->StoreInterface, session->Transaction, NULL, tmppath, "%s", tmpvalue);
    ReleaseMutex(&Fdo->SessionLock);

    if (!NT_SUCCESS(status))
        goto fail8;

    WmiFree(tmpvalue);
    FreeUTF8String(&value);
    WmiFree(tmppath);
    FreeUTF8String(&pathname);

    return STATUS_SUCCESS;

fail8:
fail7:
    WmiFree(tmpvalue);
fail6:
    FreeUTF8String(&value);
fail5:
    WmiFree(tmppath);
fail4:
    FreeUTF8String(&pathname);
fail3:
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteGetFirstChild(
    IN  PXENIFACE_FDO       Fdo,
    IN  PUNICODE_STRING     instance,
    IN  UCHAR*              InBuffer,
    IN  ULONG               InBufferSize,
    IN  UCHAR*              OutBuffer,
    IN  ULONG               OutBufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    ULONG                   RequiredSize;
    UCHAR*                  uloc;
    NTSTATUS                status;
    OEM_STRING              path;
    PCHAR                   listresults;
    size_t                  stringarraysize;
    UCHAR*                  valuepos;
    PXENSTORE_SESSION       session;
    char*                   tmppath;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &uloc,
                         WMI_DONE))
        goto fail1;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail2;

    status = GetCountedUTF8String(&path, uloc);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = WmiAllocate(path.Length + 1);
    if (tmppath == NULL)
        goto fail4;

    RtlCopyBytes(tmppath, path.Buffer, path.Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceAndLock(Fdo, instance);
    if (session == NULL)
        goto fail5;

    status = XENBUS_STORE(Directory, &Fdo->StoreInterface, session->Transaction, NULL, tmppath, &listresults);
    ReleaseMutex(&Fdo->SessionLock);

    if (!NT_SUCCESS(status))
        goto fail6;

    stringarraysize = 0;
    if ((listresults != NULL) && (listresults[0] != 0)) {
        stringarraysize += CountBytesUtf16FromUtf8String(&path);
        if ((path.Length != 1) || (path.Buffer[0] != '/')) {
            // If the path isn't '/', we need to insert a
            // '/' between pathname and nodename;
            stringarraysize += sizeof(WCHAR);
        }
        stringarraysize += GetCountedUtf8Size(listresults);
    } else {
        stringarraysize += GetCountedUtf8Size("");
    }

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(InBuffer, FALSE, &RequiredSize, OutBufferSize,
                         WMI_STRING, stringarraysize, &valuepos,
                         WMI_DONE))
        goto fail7;

    if ((listresults != NULL) && (listresults[0] != 0)) {
        PSTR fullpath;
        if ((path.Length == 1) && (path.Buffer[0] == '/'))
            fullpath = Xmasprintf("/%s", listresults);
        else
            fullpath = Xmasprintf("%s/%s", path.Buffer, listresults);

        status = STATUS_NO_MEMORY;
        if (fullpath == NULL)
            goto fail8;

        WriteCountedUTF8String(fullpath, valuepos);
        valuepos += GetCountedUtf8Size(fullpath);
        WmiFree(fullpath);
    } else {
        WriteCountedUTF8String("", valuepos);
    }

    XENBUS_STORE(Free, &Fdo->StoreInterface, listresults);

    WmiFree(tmppath);
    FreeUTF8String(&path);

    *BytesWritten = RequiredSize;
    return STATUS_SUCCESS;

fail8:
fail7:
    XENBUS_STORE(Free, &Fdo->StoreInterface, listresults);
    *BytesWritten = RequiredSize;
fail6:
fail5:
    WmiFree(tmppath);
fail4:
    FreeUTF8String(&path);
fail3:
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteGetNextSibling(
    IN  PXENIFACE_FDO       Fdo,
    IN  PUNICODE_STRING     instance,
    IN  UCHAR*              InBuffer,
    IN  ULONG               InBufferSize,
    IN  UCHAR*              OutBuffer,
    IN  ULONG               OutBufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    ULONG                   RequiredSize;
    UCHAR*                  uloc;
    NTSTATUS                status;
    OEM_STRING              path;
    ANSI_STRING             checkleaf;
    PCHAR                   listresults;
    PCHAR                   nextresult;
    size_t                  stringarraysize;
    UCHAR*                  valuepos;
    PXENSTORE_SESSION       session;
    char*                   tmppath;
    char*                   tmpleaf;
    int                     leafoffset;
    char*                   attemptstring;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &uloc,
                         WMI_DONE))
        goto fail1;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail2;

    status = GetCountedUTF8String(&path, uloc);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = WmiAllocate(path.Length + 1);
    if (tmppath == NULL)
        goto fail4;

    tmpleaf = WmiAllocate(path.Length + 1);
    if (tmpleaf == NULL)
        goto fail5;

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceAndLock(Fdo, instance);
    if (session == NULL)
        goto fail6;

    leafoffset = 0;
    if (path.Length > 1) {
        leafoffset = path.Length;
        while ((leafoffset != 0) && (path.Buffer[leafoffset] != '/'))
            leafoffset--;
    }
    if (leafoffset != 0) {
#pragma warning(suppress:6386) // buffer overrun
        RtlCopyBytes(tmppath, path.Buffer, leafoffset);
        RtlCopyBytes(tmpleaf, path.Buffer + leafoffset + 1, path.Length - leafoffset - 1);
    } else if (path.Buffer[0] == '/') {
        if (path.Length > 1)
            RtlCopyBytes(tmpleaf, path.Buffer + 1, path.Length - 1);
        tmppath[0] = '/';
    } else {
#pragma warning(suppress:6386) // buffer overrun
        RtlCopyBytes(tmpleaf, path.Buffer, path.Length);
    }

    status = XENBUS_STORE(Directory, &Fdo->StoreInterface, session->Transaction, NULL, tmppath, &listresults);
    ReleaseMutex(&Fdo->SessionLock);

    if (!NT_SUCCESS(status))
        goto fail7;

    stringarraysize = 0;
    RtlInitAnsiString(&checkleaf, tmpleaf);

    nextresult = listresults;
    while (*nextresult != 0) {
        ANSI_STRING checkstr;
        RtlInitAnsiString(&checkstr, nextresult);
        if (RtlEqualString(&checkstr, &checkleaf, TRUE))
            break;

        while (*nextresult != 0)
            nextresult++;
        nextresult++;
    }

    attemptstring = NULL;
    while (*nextresult != 0)
        nextresult++;
    nextresult++;

    if (*nextresult != 0)
        attemptstring = nextresult;

    if (attemptstring != NULL) {
        stringarraysize += CountBytesUtf16FromUtf8(tmppath); //sizeof(WCHAR)*leafoffset;
        if ((path.Length != 1) || (path.Buffer[0] != '/')) {
            // If the path isn't '/', we need to insert a
            // '/' between pathname and nodename;
            stringarraysize += sizeof(WCHAR);
        }
        stringarraysize += GetCountedUtf8Size(attemptstring);
    } else {
        stringarraysize += GetCountedUtf8Size("");
    }

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(InBuffer, FALSE, &RequiredSize, OutBufferSize,
                         WMI_STRING, stringarraysize, &valuepos,
                         WMI_DONE))
        goto fail8;

    if (attemptstring != NULL) {
        PSTR fullpath;
        if ((leafoffset == 1) && (path.Buffer[0] == '/'))
            fullpath = Xmasprintf("/%s", attemptstring);
        else
            fullpath = Xmasprintf("%s/%s", tmppath, attemptstring);

        status = STATUS_NO_MEMORY;
        if (fullpath == NULL)
            goto fail9;

        WriteCountedUTF8String(fullpath, valuepos);
        WmiFree(fullpath);
    } else {
        WriteCountedUTF8String("", valuepos);
        valuepos += GetCountedUtf8Size("");
    }

    XENBUS_STORE(Free, &Fdo->StoreInterface, listresults);

    WmiFree(tmpleaf);
    WmiFree(tmppath);
    FreeUTF8String(&path);

    *BytesWritten = RequiredSize;
    return STATUS_SUCCESS;

fail9:
fail8:
    XENBUS_STORE(Free, &Fdo->StoreInterface, listresults);
    *BytesWritten = RequiredSize;
fail7:
fail6:
    WmiFree(tmpleaf);
fail5:
    WmiFree(tmppath);
fail4:
    FreeUTF8String(&path);
fail3:
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteGetChildren(
    IN  PXENIFACE_FDO       Fdo,
    IN  PUNICODE_STRING     instance,
    IN  UCHAR*              InBuffer,
    IN  ULONG               InBufferSize,
    IN  UCHAR*              OutBuffer,
    IN  ULONG               OutBufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    int                     i;
    ULONG                   RequiredSize;
    UCHAR*                  uloc;
    NTSTATUS                status;
    OEM_STRING              path;
    PCHAR                   listresults;
    PCHAR                   nextresults;
    ULONG*                  noofnodes;
    size_t                  stringarraysize;
    UCHAR*                  valuepos;
    PXENSTORE_SESSION       session;
    char*                   tmppath;

    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &uloc,
                         WMI_DONE))
        goto fail1;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail2;

    status = GetCountedUTF8String(&path, uloc);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = WmiAllocate(path.Length + 1);
    if (tmppath == NULL)
        goto fail4;

    RtlCopyBytes(tmppath, path.Buffer, path.Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceAndLock(Fdo, instance);
    if (session == NULL)
        goto fail5;

    status = XENBUS_STORE(Directory, &Fdo->StoreInterface, session->Transaction, NULL, tmppath, &listresults);
    ReleaseMutex(&Fdo->SessionLock);

    if (!NT_SUCCESS(status))
        goto fail6;

    stringarraysize = 0;

    nextresults = listresults;
    while (*nextresults != 0) {
        stringarraysize += sizeof(WCHAR) * path.Length;
        if ((path.Length != 1) || (path.Buffer[0] != '/')) {
            // If the path isn't '/', we need to insert a
            // '/' between pathname and nodename;
            stringarraysize += sizeof(WCHAR);
        }
        stringarraysize += GetCountedUtf8Size(nextresults);

        while (*nextresults != 0)
            nextresults++;
        nextresults++;
    }

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(InBuffer, FALSE, &RequiredSize, OutBufferSize,
                         WMI_UINT32, &noofnodes,
                         WMI_STRING, stringarraysize, &valuepos,
                         WMI_DONE))
        goto fail7;

    nextresults = listresults;
    i = 0;
    while (*nextresults != 0) {
        PSTR fullpath;
        if ((path.Length == 1) && (path.Buffer[0] == '/'))
            fullpath = Xmasprintf("/%s", nextresults);
        else
            fullpath = Xmasprintf("%s/%s", path.Buffer, nextresults);

        status = STATUS_NO_MEMORY;
        if (fullpath == NULL)
            goto fail8;

        WriteCountedUTF8String(fullpath, valuepos);
        valuepos += GetCountedUtf8Size(fullpath);
        WmiFree(fullpath);

        while (*nextresults != 0)
            nextresults++;
        nextresults++;
        i++;
    }
    *noofnodes = i;

    XENBUS_STORE(Free, &Fdo->StoreInterface, listresults);
    WmiFree(tmppath);
    FreeUTF8String(&path);

    *BytesWritten = RequiredSize;
    return STATUS_SUCCESS;

fail8:
fail7:
    XENBUS_STORE(Free, &Fdo->StoreInterface, listresults);
    *BytesWritten = RequiredSize;
fail6:
fail5:
    WmiFree(tmppath);
fail4:
    FreeUTF8String(&path);
fail3:
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteLog(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    ULONG               RequiredSize;
    UCHAR*              uloc;
    NTSTATUS            status;
    ANSI_STRING         message;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &uloc,
                         WMI_DONE))
        goto fail1;

    status = GetCountedAnsiString(&message, uloc);
    if (!NT_SUCCESS(status))
        goto fail2;

    Info("USER: %s\n", message.Buffer);

    RtlFreeAnsiString(&message);

    return STATUS_SUCCESS;

fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteStartTransaction(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    NTSTATUS            status;
    PXENSTORE_SESSION   session;

    *BytesWritten = 0;
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail1;

    session = FindSessionByInstanceAndLock(Fdo, instance);
    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if (session == NULL)
        goto fail2;

    status = STATUS_REQUEST_OUT_OF_SEQUENCE;
    if (session->Transaction != NULL)
        goto fail3;

    XENBUS_STORE(TransactionStart, &Fdo->StoreInterface, &session->Transaction);

    ReleaseMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;

fail3:
    ReleaseMutex(&Fdo->SessionLock);
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteCommitTransaction(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    NTSTATUS            status;
    PXENSTORE_SESSION   session;

    *BytesWritten = 0;
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail1;

    session = FindSessionByInstanceAndLock(Fdo, instance);
    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if (session == NULL)
        goto fail2;

    status = STATUS_REQUEST_OUT_OF_SEQUENCE;
    if (session->Transaction == NULL)
        goto fail3;

    status = XENBUS_STORE(TransactionEnd, &Fdo->StoreInterface, session->Transaction, TRUE);
    session->Transaction = NULL;

    if (!NT_SUCCESS(status))
        goto fail4;

    ReleaseMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;

fail4:
fail3:
    ReleaseMutex(&Fdo->SessionLock);
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteAbortTransaction(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    NTSTATUS            status;
    PXENSTORE_SESSION   session;

    *BytesWritten = 0;
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail1;

    session = FindSessionByInstanceAndLock(Fdo, instance);
    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if (session == NULL)
        goto fail2;

    status = STATUS_REQUEST_OUT_OF_SEQUENCE;
    if (session->Transaction == NULL)
        goto fail3;

    status = XENBUS_STORE(TransactionEnd, &Fdo->StoreInterface, session->Transaction, FALSE);
    session->Transaction = NULL;

    if (!NT_SUCCESS(status))
        goto fail4;

    ReleaseMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;

fail4:
fail3:
    ReleaseMutex(&Fdo->SessionLock);
fail2:
fail1:
    return status;
}

static NTSTATUS
SessionExecuteGetValue(
    IN  PXENIFACE_FDO   Fdo,
    IN  PUNICODE_STRING instance,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    NTSTATUS            status;
    OEM_STRING          path;
    UCHAR*              uloc;
    char*               value;
    UCHAR*              valuepos;
    char*               tmppath;
    ULONG               RequiredSize;
    PXENSTORE_SESSION   session;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &uloc,
                         WMI_DONE))
        goto fail1;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!Fdo->InterfacesAcquired)
        goto fail2;

    status = GetCountedUTF8String(&path, uloc);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = WmiAllocate(path.Length + 1);
    if (tmppath == NULL)
        goto fail4;

    RtlCopyBytes(tmppath, path.Buffer, path.Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceAndLock(Fdo, instance);
    if (session == NULL)
        goto fail5;

    status = XENBUS_STORE(Read, &Fdo->StoreInterface, session->Transaction, NULL, tmppath, &value);
    ReleaseMutex(&Fdo->SessionLock);

    if (!NT_SUCCESS(status))
        goto fail6;

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(OutBuffer, FALSE, &RequiredSize, OutBufferSize,
                         WMI_STRING, GetCountedUtf8Size(value), &valuepos,
                         WMI_DONE))
        goto fail7;

    WriteCountedUTF8String(value, valuepos);

    XENBUS_STORE(Free, &Fdo->StoreInterface, value);
    WmiFree(tmppath);
    FreeUTF8String(&path);

    *BytesWritten = RequiredSize;
    return STATUS_SUCCESS;

fail7:
    XENBUS_STORE(Free, &Fdo->StoreInterface, value);
    *BytesWritten = RequiredSize;
fail6:
fail5:
    WmiFree(tmppath);
fail4:
    FreeUTF8String(&path);
fail3:
fail2:
fail1:
    return status;
}

static NTSTATUS
BaseExecuteAddSession(
    IN  PXENIFACE_FDO   Fdo,
    IN  UCHAR*          InBuffer,
    IN  ULONG           InBufferSize,
    IN  UCHAR*          OutBuffer,
    IN  ULONG           OutBufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    ULONG               RequiredSize;
    UNICODE_STRING      ustring;
    ULONG*              id;
    UCHAR*              StringId;
    NTSTATUS            status;

    *BytesWritten = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                         WMI_STRING, &StringId,
                         WMI_DONE))
        goto fail1;

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(OutBuffer, FALSE, &RequiredSize, OutBufferSize,
                         WMI_UINT32, &id,
                         WMI_DONE))
        goto fail2;

    AllocUnicodeStringBuffer(&ustring, *(USHORT*)(StringId));
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (ustring.Buffer == NULL)
        goto fail3;

    status = RtlUnicodeStringCbCopyStringN(&ustring,
                                           (LPCWSTR)(StringId + sizeof(USHORT)),
                                           *(USHORT*)(StringId));
    if (!NT_SUCCESS(status))
        goto fail4;

    status = SessionCreate(Fdo, &ustring, id);
    if (!NT_SUCCESS(status))
        goto fail5;

    *BytesWritten = RequiredSize;
    return STATUS_SUCCESS;

fail5:
fail4:
    FreeUnicodeStringBuffer(&ustring);
fail3:
fail2:
    *BytesWritten = RequiredSize;
fail1:
    return status;
}

static NTSTATUS
SessionExecuteMethod(
    IN  PXENIFACE_FDO   Fdo,
    IN  UCHAR*          Buffer,
    IN  ULONG           BufferSize,
    OUT ULONG_PTR*      BytesWritten
    )
{
    ULONG               RequiredSize;
    WNODE_METHOD_ITEM*  Method;
    UCHAR*              InBuffer;
    NTSTATUS            status;
    UNICODE_STRING      instance;
    UCHAR*              InstStr;

    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_METHOD_ITEM), &Method,
                         WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;

    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_METHOD_ITEM), &Method,
                         WMI_STRINGOFFSET, Method->OffsetInstanceName, &InstStr,
                         WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;

    InBuffer = Buffer + Method->DataBlockOffset;

    GetCountedUnicodeString(&instance, InstStr);

    switch (Method->MethodId) {
    case GetValue:
        status = SessionExecuteGetValue(Fdo,
                                        &instance,
                                        InBuffer,
                                        Method->SizeDataBlock,
                                        Buffer + Method->DataBlockOffset,
                                        BufferSize - Method->DataBlockOffset,
                                        BytesWritten);
        break;
    case SetValue:
        status = SessionExecuteSetValue(Fdo,
                                        &instance,
                                        InBuffer,
                                        Method->SizeDataBlock,
                                        Buffer + Method->DataBlockOffset,
                                        BufferSize - Method->DataBlockOffset,
                                        BytesWritten);
        break;
    case GetChildren:
        status = SessionExecuteGetChildren(Fdo,
                                           &instance,
                                           InBuffer,
                                           Method->SizeDataBlock,
                                           Buffer + Method->DataBlockOffset,
                                           BufferSize - Method->DataBlockOffset,
                                           BytesWritten);
        break;
    case SetWatch:
        status = SessionExecuteSetWatch(Fdo,
                                        &instance,
                                        InBuffer, Method->SizeDataBlock,
                                        Buffer + Method->DataBlockOffset,
                                        BufferSize - Method->DataBlockOffset,
                                        BytesWritten);
        break;
    case EndSession:
        status = SessionExecuteEndSession(Fdo,
                                          &instance,
                                          InBuffer,
                                          Method->SizeDataBlock,
                                          Buffer + Method->DataBlockOffset,
                                          BufferSize - Method->DataBlockOffset,
                                          BytesWritten);
        break;
    case RemoveWatch:
        status = SessionExecuteRemoveWatch(Fdo,
                                           &instance,
                                           InBuffer,
                                           Method->SizeDataBlock,
                                           Buffer + Method->DataBlockOffset,
                                           BufferSize - Method->DataBlockOffset,
                                           BytesWritten);
        break;
    case RemoveValue:
        status = SessionExecuteRemoveValue(Fdo,
                                           &instance,
                                           InBuffer,
                                           Method->SizeDataBlock,
                                           Buffer + Method->DataBlockOffset,
                                           BufferSize - Method->DataBlockOffset,
                                           BytesWritten);
        break;
    case Log:
        status = SessionExecuteLog(Fdo,
                                   &instance,
                                   InBuffer,
                                   Method->SizeDataBlock,
                                   Buffer + Method->DataBlockOffset,
                                   BufferSize - Method->DataBlockOffset,
                                   BytesWritten);
        break;
    case StartTransaction:
        status = SessionExecuteStartTransaction(Fdo,
                                                &instance,
                                                InBuffer,
                                                Method->SizeDataBlock,
                                                Buffer + Method->DataBlockOffset,
                                                BufferSize - Method->DataBlockOffset,
                                                BytesWritten);
        break;
    case CommitTransaction:
        status = SessionExecuteCommitTransaction(Fdo,
                                                 &instance,
                                                 InBuffer,
                                                 Method->SizeDataBlock,
                                                 Buffer + Method->DataBlockOffset,
                                                 BufferSize - Method->DataBlockOffset,
                                                 BytesWritten);
        break;
    case AbortTransaction:
        status = SessionExecuteAbortTransaction(Fdo,
                                                &instance,
                                                InBuffer,
                                                Method->SizeDataBlock,
                                                Buffer + Method->DataBlockOffset,
                                                BufferSize - Method->DataBlockOffset,
                                                BytesWritten);
        break;
    case GetFirstChild:
        status = SessionExecuteGetFirstChild(Fdo,
                                             &instance,
                                             InBuffer,
                                             Method->SizeDataBlock,
                                             Buffer + Method->DataBlockOffset,
                                             BufferSize - Method->DataBlockOffset,
                                             BytesWritten);
        break;
    case GetNextSibling:
        status = SessionExecuteGetNextSibling(Fdo,
                                              &instance,
                                              InBuffer,
                                              Method->SizeDataBlock,
                                              Buffer + Method->DataBlockOffset,
                                              BufferSize - Method->DataBlockOffset,
                                              BytesWritten);
        break;
    default:
        Info("DRV: Unknown WMI method %d\n", Method->MethodId);
        return STATUS_WMI_ITEMID_NOT_FOUND;
    }

    Method->SizeDataBlock = (ULONG)*BytesWritten;
    *BytesWritten += Method->DataBlockOffset;
    if (status == STATUS_BUFFER_TOO_SMALL)
        return NodeTooSmall(Buffer, BufferSize, (ULONG)*BytesWritten, BytesWritten);

    Method->WnodeHeader.BufferSize = (ULONG)*BytesWritten;
    return status;
}

static NTSTATUS
BaseExecuteMethod(
    IN  PXENIFACE_FDO       Fdo,
    IN  UCHAR*              Buffer,
    IN  ULONG               BufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    ULONG                   RequiredSize;
    WNODE_METHOD_ITEM*      Method;
    UCHAR*                  InBuffer;
    NTSTATUS                status;

    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_METHOD_ITEM), &Method,
                         WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;

    InBuffer = Buffer + Method->DataBlockOffset;

    switch (Method->MethodId) {
    case AddSession:
        status = BaseExecuteAddSession(Fdo,
                                       InBuffer,
                                       Method->SizeDataBlock,
                                       Buffer + Method->DataBlockOffset,
                                       BufferSize - Method->DataBlockOffset,
                                       BytesWritten);
        break;

    default:
        return STATUS_WMI_ITEMID_NOT_FOUND;
    }

    Method->SizeDataBlock = (ULONG)*BytesWritten;
    *BytesWritten += Method->DataBlockOffset;
    Method->WnodeHeader.BufferSize = (ULONG)*BytesWritten;

    return status;
}

static NTSTATUS
WmiExecuteMethod(
    IN  PXENIFACE_FDO       Fdo,
    IN  PIO_STACK_LOCATION  Stack,
    OUT ULONG_PTR*          BytesWritten
    )
{
    if (IsEqualGUID(Stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreBase)))
        return BaseExecuteMethod(Fdo,
                                 Stack->Parameters.WMI.Buffer,
                                 Stack->Parameters.WMI.BufferSize,
                                 BytesWritten);

    if (IsEqualGUID(Stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreSession)))
        return SessionExecuteMethod(Fdo,
                                    Stack->Parameters.WMI.Buffer,
                                    Stack->Parameters.WMI.BufferSize,
                                    BytesWritten);

    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS
GenerateSessionBlock(
    IN  PXENIFACE_FDO       Fdo,
    IN  UCHAR*              Buffer,
    IN  ULONG               BufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    PLIST_ENTRY             ListEntry;
    PXENSTORE_SESSION       Session;
    WNODE_ALL_DATA*         node;
    ULONG                   RequiredSize;
    size_t                  nodesizerequired;
    size_t                  namesizerequired;
    int                     entries;
    OFFSETINSTANCEDATAANDLENGTH* dataoffsets;
    ULONG*                  nameoffsets;
    UCHAR*                  data;
    UCHAR*                  names;
    int                     entrynum = 0;
    UCHAR*                  datapos;
    UCHAR*                  namepos;

    AcquireMutex(&Fdo->SessionLock);

    //work out how much space we need for each session structure
    nodesizerequired = 0;
    namesizerequired = 0;
    entries = 0;

    for (ListEntry = Fdo->SessionHead.Flink;
         ListEntry != &Fdo->SessionHead;
         ListEntry = ListEntry->Flink) {
        ULONG *id;
        UCHAR *sesbuf;
        UCHAR *inamebuf;

        Session = CONTAINING_RECORD(ListEntry, XENSTORE_SESSION, ListEntry);

        (VOID) AccessWmiBuffer((PUCHAR)nodesizerequired, FALSE, &RequiredSize, 0,
                        WMI_UINT32, &id,
                        WMI_STRING, GetCountedUnicodeStringSize(&Session->StringId), &sesbuf,
                        WMI_DONE);
        nodesizerequired += RequiredSize;

        (VOID) AccessWmiBuffer((PUCHAR)namesizerequired, FALSE, &RequiredSize, 0,
                        WMI_STRING, GetCountedUnicodeStringSize(&Session->InstanceName), &inamebuf,
                        WMI_DONE);
        namesizerequired += RequiredSize;
        entries++;
    }

    // perform the access check
    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_ALL_DATA), &node,
                         WMI_BUFFER, sizeof(OFFSETINSTANCEDATAANDLENGTH) * entries, &dataoffsets,
                         WMI_BUFFER, sizeof(ULONG)*entries, &nameoffsets,
                         WMI_BUFFER, nodesizerequired, &data,
                         WMI_BUFFER, namesizerequired, &names,
                         WMI_DONE)) {
        ReleaseMutex(&Fdo->SessionLock);
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, BytesWritten);
    }

    node->DataBlockOffset = (ULONG)(data - Buffer);
    node->OffsetInstanceNameOffsets = (ULONG)((UCHAR *)nameoffsets - Buffer);
    node->WnodeHeader.BufferSize = RequiredSize;
    KeQuerySystemTime(&node->WnodeHeader.TimeStamp);
    node->WnodeHeader.Flags = WNODE_FLAG_ALL_DATA;
    node->InstanceCount = entries;

    *BytesWritten = RequiredSize;

    datapos = data;
    namepos = names;

    //work out names for each session entry
    for (ListEntry = Fdo->SessionHead.Flink;
         ListEntry != &Fdo->SessionHead;
         ListEntry = ListEntry->Flink) {
        ULONG *id;
        UCHAR *sesbuf;
        UCHAR *inamebuf;

        Session = CONTAINING_RECORD(ListEntry, XENSTORE_SESSION, ListEntry);

        (VOID) AccessWmiBuffer(datapos, FALSE, &RequiredSize, BufferSize+Buffer-datapos,
                        WMI_UINT32, &id,
                        WMI_STRING, GetCountedUnicodeStringSize(&Session->StringId), &sesbuf,
                        WMI_DONE);

        node->OffsetInstanceDataAndLength[entrynum].OffsetInstanceData =
            (ULONG)((UCHAR *)id - Buffer);
        node->OffsetInstanceDataAndLength[entrynum].LengthInstanceData =
            RequiredSize;
        *id = Session->SessionId;
        WriteCountedUnicodeString(&Session->StringId, sesbuf);
        datapos += RequiredSize;

        (VOID) AccessWmiBuffer(namepos, FALSE, &RequiredSize, BufferSize+Buffer-namepos,
                        WMI_STRING, GetCountedUnicodeStringSize(&Session->InstanceName), &inamebuf,
                        WMI_DONE);

        nameoffsets[entrynum] = (ULONG)(namepos-Buffer);
        WriteCountedUnicodeString(&Session->InstanceName, inamebuf);
        namepos += RequiredSize;

        namesizerequired += RequiredSize;
        entrynum++;
    }

    ReleaseMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;
}

static NTSTATUS
GenerateBaseBlock(
    IN  PXENIFACE_FDO       Fdo,
    IN  UCHAR*              Buffer,
    IN  ULONG               BufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    WNODE_ALL_DATA*         node;
    ULONG                   RequiredSize;
    ULONGLONG*              time;

    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_ALL_DATA), &node,
                         WMI_UINT64, &time,
                         WMI_DONE))
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, BytesWritten);

    node->DataBlockOffset = (ULONG)(((UCHAR *)time) - Buffer);
    node->WnodeHeader.BufferSize = RequiredSize;
    KeQuerySystemTime(&node->WnodeHeader.TimeStamp);
    node->WnodeHeader.Flags = WNODE_FLAG_ALL_DATA |
                              WNODE_FLAG_FIXED_INSTANCE_SIZE |
                              WNODE_FLAG_PDO_INSTANCE_NAMES;
    if (Fdo->InterfacesAcquired) {
        LARGE_INTEGER info;

        XENBUS_SHARED_INFO(GetTime, &Fdo->SharedInfoInterface, &info, NULL);
        *time = info.QuadPart;
    } else {
        *time = 0;
    }

    node->InstanceCount = 1;
    node->FixedInstanceSize = sizeof(ULONGLONG);

    *BytesWritten = RequiredSize;
    return STATUS_SUCCESS;
}

static NTSTATUS
GenerateBaseInstance(
    IN  PXENIFACE_FDO       Fdo,
    IN  UCHAR*              Buffer,
    IN  ULONG               BufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    WNODE_SINGLE_INSTANCE*  node;
    ULONG                   RequiredSize;
    ULONGLONG*              time;
    UCHAR*                  dbo;

    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                         WMI_DONE))
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, BytesWritten);

    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                         WMI_OFFSET, node->DataBlockOffset, 0 ,&dbo,
                         WMI_DONE))
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, BytesWritten);

    if (!AccessWmiBuffer(dbo, FALSE, &RequiredSize, BufferSize - node->DataBlockOffset,
                         WMI_UINT64, &time,
                         WMI_DONE))
        return NodeTooSmall(Buffer,
                            BufferSize,
                            RequiredSize + node->DataBlockOffset,
                            BytesWritten);

    if (node->InstanceIndex != 0)
        return STATUS_WMI_ITEMID_NOT_FOUND;

    if (Fdo->InterfacesAcquired) {
        LARGE_INTEGER info;

        XENBUS_SHARED_INFO(GetTime, &Fdo->SharedInfoInterface, &info, NULL);
        *time = info.QuadPart;
    } else {
        *time = 0;
    }

    node->WnodeHeader.BufferSize = node->DataBlockOffset + RequiredSize;
    node->SizeDataBlock = RequiredSize;

    *BytesWritten = node->DataBlockOffset + RequiredSize;

    return STATUS_SUCCESS;
}

static NTSTATUS
GenerateSessionInstance(
    IN  PXENIFACE_FDO       Fdo,
    IN  UCHAR*              Buffer,
    IN  ULONG               BufferSize,
    OUT ULONG_PTR*          BytesWritten
    )
{
    WNODE_SINGLE_INSTANCE*  node;
    ULONG                   RequiredSize;
    UCHAR*                  dbo;
    UCHAR*                  InstStr;
    UNICODE_STRING          instance;
    ULONG*                  id;
    PXENSTORE_SESSION       session;
    UCHAR*                  sesbuf;
    NTSTATUS                status;

    *BytesWritten = 0;
    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                         WMI_DONE))
        goto fail1;

    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                         WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                         WMI_STRINGOFFSET, node->OffsetInstanceName, &InstStr,
                         WMI_OFFSET, node->DataBlockOffset, 0, &dbo,
                         WMI_DONE))
        goto fail2;

    GetCountedUnicodeString(&instance, InstStr);

    AcquireMutex(&Fdo->SessionLock);
    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    session = FindSessionByInstanceLocked(Fdo, &instance);
    if (session == NULL)
        goto fail3;

    if (!AccessWmiBuffer(dbo, FALSE, &RequiredSize, BufferSize-node->DataBlockOffset,
                         WMI_UINT32, &id,
                         WMI_STRING, GetCountedUnicodeStringSize(&session->StringId), &sesbuf,
                         WMI_DONE))
        goto fail4;

    *id = session->SessionId;
    WriteCountedUnicodeString(&session->StringId, sesbuf);
    ReleaseMutex(&Fdo->SessionLock);

    node->SizeDataBlock = RequiredSize;
    node->WnodeHeader.BufferSize = node->DataBlockOffset + RequiredSize;

    *BytesWritten = node->DataBlockOffset + RequiredSize;

    return STATUS_SUCCESS;

fail4:
    ReleaseMutex(&Fdo->SessionLock);
    return NodeTooSmall(Buffer, BufferSize, RequiredSize + node->DataBlockOffset, BytesWritten);

fail3:
    ReleaseMutex(&Fdo->SessionLock);
    return status;

fail2:
fail1:
    return NodeTooSmall(Buffer, BufferSize, RequiredSize, BytesWritten);
}

NTSTATUS
WmiQueryAllData(
    IN  PXENIFACE_FDO       Fdo,
    IN  PIO_STACK_LOCATION  Stack,
    OUT ULONG_PTR*          BytesWritten
    )
{
    if (IsEqualGUID(Stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreBase)))
        return GenerateBaseBlock(Fdo,
                                 Stack->Parameters.WMI.Buffer,
                                 Stack->Parameters.WMI.BufferSize,
                                 BytesWritten);

    if (IsEqualGUID(Stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreSession)))
        return GenerateSessionBlock(Fdo,
                                    Stack->Parameters.WMI.Buffer,
                                    Stack->Parameters.WMI.BufferSize,
                                    BytesWritten);

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
WmiQuerySingleInstance(
    IN  PXENIFACE_FDO       Fdo,
    IN  PIO_STACK_LOCATION  Stack,
    OUT ULONG_PTR*          BytesWritten
    )
{
    if (IsEqualGUID(Stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreBase)))
        return GenerateBaseInstance(Fdo,
                                    Stack->Parameters.WMI.Buffer,
                                    Stack->Parameters.WMI.BufferSize,
                                    BytesWritten);

    if (IsEqualGUID(Stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreSession)))
        return GenerateSessionInstance(Fdo,
                                       Stack->Parameters.WMI.Buffer,
                                       Stack->Parameters.WMI.BufferSize,
                                       BytesWritten);

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
WmiRegInfo(
    IN  PXENIFACE_FDO       Fdo,
    IN  PIO_STACK_LOCATION  Stack,
    OUT ULONG_PTR*          BytesWritten
   )
{
    size_t                  mofnamesz;
    WMIREGGUID*             guid;
    WMIREGINFO*             reginfo;
    WMIREGGUID*             guiddata;
    UCHAR*                  mofnameptr;
    UCHAR*                  regpath;
    ULONG                   RequiredSize;

    const int entries = 4;
    const static UNICODE_STRING mofname = RTL_CONSTANT_STRING(L"XENIFACEMOF");

    Trace("%s\n",__FUNCTION__);

    if  (Stack->Parameters.WMI.DataPath == WMIREGISTER)
        mofnamesz = mofname.Length + sizeof(USHORT);
    else
        mofnamesz = 0;

    if (!AccessWmiBuffer(Stack->Parameters.WMI.Buffer, FALSE,
                         &RequiredSize,
                         Stack->Parameters.WMI.BufferSize,
                         WMI_BUFFER, sizeof(WMIREGINFO), (UCHAR **)&reginfo,
                         WMI_BUFFER, entries * sizeof(WMIREGGUID), (UCHAR **)&guiddata,
                         WMI_STRING, mofnamesz, &mofnameptr,
                         WMI_STRING, DriverParameters.RegistryPath.Length + sizeof(USHORT), &regpath,
                         WMI_DONE)) {
        reginfo->BufferSize = RequiredSize;
        *BytesWritten = sizeof(ULONG);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (Stack->Parameters.WMI.DataPath == WMIREGISTER) {
        reginfo->MofResourceName = (ULONG)((ULONG_PTR)mofnameptr - (ULONG_PTR)reginfo);
        WriteCountedUnicodeString(&mofname, mofnameptr);
        reginfo->RegistryPath = (ULONG)((ULONG_PTR)regpath - (ULONG_PTR)reginfo);
        WriteCountedUnicodeString(&DriverParameters.RegistryPath, regpath);
    }

    reginfo->BufferSize = RequiredSize;
    reginfo->NextWmiRegInfo = 0;
    reginfo->GuidCount = entries;

    guid = &reginfo->WmiRegGuid[0];
    guid->InstanceCount = 1;
    guid->Guid = OBJECT_GUID(XenStoreBase);
    guid->Flags = WMIREG_FLAG_INSTANCE_PDO;
    guid->Pdo = (ULONG_PTR)Fdo->PhysicalDeviceObject;
    ObReferenceObject(Fdo->PhysicalDeviceObject);

    guid = &reginfo->WmiRegGuid[1];
    guid->Guid = OBJECT_GUID(XenStoreSession);
    guid->Flags = 0;

    guid = &reginfo->WmiRegGuid[2];
    guid->InstanceCount = 1;
    guid->Guid = OBJECT_GUID(XenStoreWatchEvent);
    guid->Flags = WMIREG_FLAG_INSTANCE_PDO |
                  WMIREG_FLAG_EVENT_ONLY_GUID ;
    guid->Pdo = (ULONG_PTR)Fdo->PhysicalDeviceObject;
    ObReferenceObject(Fdo->PhysicalDeviceObject);

    guid = &reginfo->WmiRegGuid[3];
    guid->InstanceCount = 1;
    guid->Guid = OBJECT_GUID(XenStoreUnsuspendedEvent);
    guid->Flags = WMIREG_FLAG_INSTANCE_PDO |
                  WMIREG_FLAG_EVENT_ONLY_GUID ;
    guid->Pdo = (ULONG_PTR)Fdo->PhysicalDeviceObject;
    ObReferenceObject(Fdo->PhysicalDeviceObject);

    *BytesWritten = RequiredSize;
    return STATUS_SUCCESS;
}

NTSTATUS
WmiRegInfoEx(
    IN  PXENIFACE_FDO       Fdo,
    IN  PIO_STACK_LOCATION  Stack,
    OUT ULONG_PTR*          BytesWritten
    )
{
    Trace("%s\n",__FUNCTION__);
    return WmiRegInfo(Fdo, Stack, BytesWritten);
}

NTSTATUS
WmiProcessMinorFunction(
    IN  PXENIFACE_FDO   Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  Stack;

    Stack = IoGetCurrentIrpStackLocation(Irp);

    if (Stack->Parameters.WMI.ProviderId != (ULONG_PTR)Fdo->Dx->DeviceObject) {
        Trace("ProviderID %p %p",
              Stack->Parameters.WMI.ProviderId,
              Fdo->PhysicalDeviceObject);
        return STATUS_NOT_SUPPORTED;
    } else {
        Trace("ProviderID Match %p %p",
              Stack->Parameters.WMI.ProviderId,
              Fdo->PhysicalDeviceObject);
    }

    switch (Stack->MinorFunction) {
    case IRP_MN_EXECUTE_METHOD:
        return WmiExecuteMethod(Fdo, Stack,  &Irp->IoStatus.Information);
    case IRP_MN_QUERY_ALL_DATA:
        return WmiQueryAllData(Fdo, Stack, &Irp->IoStatus.Information);
    case IRP_MN_QUERY_SINGLE_INSTANCE:
        return WmiQuerySingleInstance(Fdo, Stack, &Irp->IoStatus.Information);
    case IRP_MN_REGINFO:
        return WmiRegInfo(Fdo, Stack, &Irp->IoStatus.Information);
    case IRP_MN_REGINFO_EX:
        return WmiRegInfoEx(Fdo, Stack, &Irp->IoStatus.Information);
    default:
        return STATUS_NOT_SUPPORTED;
    }
}

VOID
WmiFireSuspendEvent(
    IN  PXENIFACE_FDO   Fdo
    )
{
    Info("Ready to unsuspend Event\n");
    KeSetEvent(&Fdo->registryWriteEvent, IO_NO_INCREMENT, FALSE);

    if (!Fdo->WmiReady)
        return;

    Trace("Fire Suspend Event\n");
    WmiFireEvent(Fdo->Dx->DeviceObject,
                 (LPGUID)&OBJECT_GUID(XenStoreUnsuspendedEvent),
                 0,
                 0,
                 NULL);
}

VOID
WmiSessionsSuspendAll(
    IN  PXENIFACE_FDO   Fdo
    )
{
    PLIST_ENTRY         ListEntry;
    PXENSTORE_SESSION   Session;

    AcquireMutex(&Fdo->SessionLock);
    Trace("Suspend all sessions\n");
    for (ListEntry = Fdo->SessionHead.Flink;
         ListEntry != &Fdo->SessionHead;
         ListEntry = ListEntry->Flink) {
        Session = CONTAINING_RECORD(ListEntry, XENSTORE_SESSION, ListEntry);

        SessionsSuspendLocked(Fdo, Session);
    }
    ReleaseMutex(&Fdo->SessionLock);
}

VOID
WmiSessionsResumeAll(
    IN  PXENIFACE_FDO   Fdo
    )
{
    PLIST_ENTRY         ListEntry;
    PXENSTORE_SESSION   Session;

    AcquireMutex(&Fdo->SessionLock);
    Trace("Resume all sessions\n");
    for (ListEntry = Fdo->SessionHead.Flink;
         ListEntry != &Fdo->SessionHead;
         ListEntry = ListEntry->Flink) {
        Session = CONTAINING_RECORD(ListEntry, XENSTORE_SESSION, ListEntry);

        SessionResumeLocked(Session);
    }
    ReleaseMutex(&Fdo->SessionLock);
}

NTSTATUS
WmiRegister(
    IN  PXENIFACE_FDO   Fdo
    )
{
    NTSTATUS            status;

    if (Fdo->WmiReady)
        return STATUS_SUCCESS;

    Trace("%s\n",__FUNCTION__);
    Info("DRV: XenIface WMI Initialisation\n");

    status = IoWMIRegistrationControl(Fdo->Dx->DeviceObject,
                                      WMIREG_ACTION_REGISTER);
    if (!NT_SUCCESS(status))
        goto fail1;

    Fdo->WmiReady = 1;
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}

VOID
WmiDeregister(
    IN  PXENIFACE_FDO   Fdo
    )
{
    if (!Fdo->WmiReady)
        return;

    Info("DRV: XenIface WMI Finalisation\n");
    Trace("%s\n",__FUNCTION__);

    SessionsRemoveAll(Fdo);
    (VOID) IoWMIRegistrationControl(Fdo->Dx->DeviceObject,
                                    WMIREG_ACTION_DEREGISTER);
    Fdo->WmiReady = 0;
}

NTSTATUS
WmiInitialize(
    IN  PXENIFACE_FDO   Fdo
    )
{
    NTSTATUS            status;

    status = IoWMISuggestInstanceName(Fdo->PhysicalDeviceObject,
                                      NULL,
                                      FALSE,
                                      &Fdo->SuggestedInstanceName);
    if (!NT_SUCCESS(status))
        goto fail1;

    Fdo->Sessions = 0;
    InitializeListHead(&Fdo->SessionHead);
    InitializeMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}

VOID
WmiTeardown(
    IN  PXENIFACE_FDO   Fdo
    )
{
    ASSERT(Fdo->Sessions == 0);

    RtlZeroMemory(&Fdo->SessionLock, sizeof(FAST_MUTEX));
    RtlZeroMemory(&Fdo->SessionHead, sizeof(LIST_ENTRY));

    RtlFreeUnicodeString(&Fdo->SuggestedInstanceName);
    RtlZeroMemory(&Fdo->SuggestedInstanceName, sizeof(UNICODE_STRING));
}
