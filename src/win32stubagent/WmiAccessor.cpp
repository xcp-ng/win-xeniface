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

#include "stdafx.h"
#define _WIN32_DCOM
#include <windows.h>
#include <iostream>
#include <algorithm>
#include <hash_map>
#include <stdio.h>
#include "winerror.h"
#include "WMIAccessor.h"
#include "XService.h"
#include "comutil.h"

//#include "xs_private.h"
#include <wbemidl.h>

#include <version.h>

#define WIDEN2(x) L ## x
#define WIDEN(x) WIDEN2(x)

#define OBJECT_NAME_A(_Name) OBJECT_PREFIX_STR "XenStore" #_Name
#define OBJECT_NAME_W(_Name) WIDEN(OBJECT_PREFIX_STR) L"XenStore" WIDEN(#_Name)

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "comsuppw.lib")

BSTR mkBstr(const char *string, size_t len) {
    BSTR res = NULL;
    size_t returned;
    wchar_t* wstring = new wchar_t[len+1];
    if (wstring == NULL) {
        goto malloc_wstring;
    }
    mbstowcs_s(&returned, wstring, len+1, string, len);
    res = SysAllocString(wstring);
    delete wstring;
malloc_wstring:
    return res;
}

char * formatCharStrInt(const char *fmt, va_list l) {
    char *buf = NULL;
    int cnt = _vscprintf(fmt, l);
    buf = (char *)XsAlloc(cnt+1);
    if (buf == NULL) {
        goto malloc_buf;
    }
    _vsnprintf(buf, cnt+1, fmt, l);
malloc_buf:
    return buf;
}

char * formatCharStr(const char *fmt, ... ) {
    char *buf =NULL;
    va_list l;
    va_start(l, fmt);
    buf = formatCharStrInt(fmt, l);
    va_end(l);
    return buf;
}

BSTR formatBstr(const char *fmt, ...) 
{
    char *buf;
    va_list l;  
    BSTR res = NULL;
    va_start(l, fmt);
    buf = formatCharStrInt(fmt, l);
    va_end(l);
    res = mkBstr(buf, strlen(buf));
    XsFree(buf);
    return res;
}

int setVariantString(VARIANT* var, const char *data, size_t len) {
    int err=-1;
    VariantInit(var);
    var->vt=VT_BSTR;
    var->bstrVal = mkBstr(data, len);
    if (var->bstrVal == NULL) {
        goto sysalloc;
    }
    err=0;
sysalloc:
    return err;
}


int setVariantString(VARIANT* var, const char *string) {
    return setVariantString(var, string, strlen(string));
}


class WatchSink : public IWbemObjectSink
{
    LONG m_lRef;
    bool bDone; 
    HANDLE triggerevent;
    HANDLE triggererror;
public:
    char *path;
    WatchSink(HANDLE event, HANDLE errorevent, const char *path) { 
        m_lRef = 1; 
        triggerevent = event;
        triggererror = errorevent;
        this->path = NULL;
        if (path) {
            this->path=(char *)XsAlloc(strlen(path)+1);
            strcpy(this->path, path);
        }
    }
   ~WatchSink() { bDone = TRUE; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();        
    virtual HRESULT STDMETHODCALLTYPE 
        QueryInterface(REFIID riid, void** ppv);

    virtual HRESULT STDMETHODCALLTYPE Indicate( 
            /* [in] */
            LONG lObjectCount,
            /* [size_is][in] */
            IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray
            );
        
    virtual HRESULT STDMETHODCALLTYPE SetStatus( 
            /* [in] */ LONG lFlags,
            /* [in] */ HRESULT hResult,
            /* [in] */ BSTR strParam,
            /* [in] */ IWbemClassObject __RPC_FAR *pObjParam
            );
};


ULONG WatchSink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

ULONG WatchSink::Release()
{
    LONG lRef = InterlockedDecrement(&m_lRef);
    if(lRef == 0)
        delete this;
    return lRef;
}

HRESULT WatchSink::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink *) this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    else return E_NOINTERFACE;
}


HRESULT WatchSink::Indicate(long lObjCount, IWbemClassObject **pArray)
{
    for (long i = 0; i < lObjCount; i++)
    {
        IWbemClassObject *pObj = pArray[i];
        SetEvent(this->triggerevent);
        // ... use the object.

        // AddRef() is only required if the object will be held after
        // the return to the caller.
    }

    return WBEM_S_NO_ERROR;
}

HRESULT WatchSink::SetStatus(
            /* [in] */ LONG lFlags,
            /* [in] */ HRESULT hResult,
            /* [in] */ BSTR strParam,
            /* [in] */ IWbemClassObject __RPC_FAR *pObjParam
        )
{
    if (FAILED(hResult)) {
        XsLog("WMI Asyc watch failed %p\n", this);
        SetEvent(this->triggererror);
    }
    return WBEM_S_NO_ERROR;
}



struct WMIAccessor
{
    IWbemServices *mpSvc;
    IWbemServices *mpXSSvc;
    
    HANDLE owning_thread;
};

struct WMIAccessor *wmi = NULL;

static string wstring2string(const wstring& wstr)
{ 
    int len;

    len = WideCharToMultiByte(CP_UTF8,
                              0,
                              wstr.c_str(),
                              -1,
                              NULL,
                              0,
                              NULL,
                              NULL);

    string str(len, 0);

    len = WideCharToMultiByte(CP_UTF8,
                              0,
                              wstr.c_str(),
                              -1,
                              &str[0],
                              (int)str.length(),
                              NULL,
                              NULL);

    return str;
}

static string bstr2string(const BSTR& bstr)
{
    wstring wstr(bstr);

    return wstring2string(wstr);
}

IWbemClassObject *getClass(WMIAccessor **wmi, BSTR path) {
    if (*wmi == NULL)
        return NULL;

    if ((*wmi)->mpXSSvc == NULL)
        return NULL;

    IWbemClassObject *returnedObject;
    HRESULT hres = (*wmi)->mpXSSvc->GetObject(path,WBEM_FLAG_RETURN_WBEM_COMPLETE,
            NULL, &returnedObject, NULL);
    if (FAILED(hres)) {
        returnedObject =NULL;
    }
    return returnedObject;
}

IWbemClassObject *getObject(WMIAccessor **wmi, BSTR path) {
    IEnumWbemClassObject *returnedEnum;
    IWbemClassObject *returnedObject;
    if (*wmi == NULL)
        return NULL;
    ASSERT((*wmi)->mpXSSvc != NULL);
    HRESULT hres =  (*wmi)->mpXSSvc->CreateInstanceEnum(path, WBEM_FLAG_FORWARD_ONLY, 
                                            NULL, 
                                            &returnedEnum);
    if (FAILED(hres)) {
        OutputDebugString("GetEnum failed\n");
        returnedObject =NULL;
        return returnedObject;
    }
    ULONG objects;

    hres = returnedEnum->Next(WBEM_INFINITE, 1, &returnedObject, &objects);

                
    if (FAILED(hres) || objects < 1) {
        OutputDebugString("GetFromEnum failed\n");
        returnedObject =NULL;
    }

    return returnedObject;
}

HRESULT methodExec(WMIAccessor** wmi,  IWbemClassObject* instance, const wchar_t *methodname, IWbemClassObject *inMethodInst, IWbemClassObject **outMethodInst)
{
    HRESULT hres=E_FAIL ;

    IWbemClassObject *outstore=NULL;
    BSTR bpathname = SysAllocString(L"__PATH");
    if (bpathname == NULL){
        goto allocpathname;
    }


    VARIANT instancepath;
    VariantInit(&instancepath);
    hres = instance->Get(bpathname, 0, &instancepath, NULL, NULL);
    if (FAILED(hres)) {
        goto getclassname;
    }


    BSTR bmethodname = SysAllocString(methodname);
    if (bmethodname == NULL){
        goto allocmethodname;
    }

    hres = (*wmi)->mpXSSvc->ExecMethod(instancepath.bstrVal, bmethodname, 0, NULL,inMethodInst, &outstore, NULL);
    if (outMethodInst != NULL) {
        *outMethodInst = NULL;
        if (!FAILED(hres)){
            *outMethodInst = outstore;
        }
    }

    SysFreeString(bmethodname);
allocmethodname:

getclassname:
    VariantClear(&instancepath);
    SysFreeString(bpathname);
allocpathname:
    return hres;
}
static IEnumWbemClassObject* runXSQuery(WMIAccessor **wmi, BSTR query)
{
    if (wmi == NULL)
        return NULL;

    ASSERT((*wmi)->mpXSSvc != NULL);

    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = (*wmi)->mpXSSvc->ExecQuery(L"WQL", 
                                         query,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
                                         NULL,
                                         &pEnumerator);
    if (FAILED(hres))
    {
        DBGPRINT(("ExecQuery failed\n"));
        pEnumerator = NULL;
    }
    return pEnumerator;
}
static IEnumWbemClassObject* runQuery(WMIAccessor *wmi, BSTR query)
{
    if (wmi == NULL)
        return NULL;

    ASSERT(wmi->mpSvc != NULL);

    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = wmi->mpSvc->ExecQuery(L"WQL", 
                                         query,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
                                         NULL,
                                         &pEnumerator);
    if (FAILED(hres))
    {
        DBGPRINT(("ExecQuery failed\n"));
        pEnumerator = NULL;
    }
    return pEnumerator;
}

LONG wmicount = 0;
static BOOLEAN com_initialized = false;
static IWbemLocator *locator = 0;
BOOL InitCom(void) {
    HRESULT hres;
    XsLog("Init COM");
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        goto err_out;
    }
    com_initialized = TRUE;
    //wmi->owning_thread = GetCurrentThread();
    //XsLog("Wmi connect thread %p", GetCurrentThread());
    // Initialize COM security.  Most of this is irrelevant to us.
    XsLog("Init security");
    hres = CoInitializeSecurity(
        NULL,     /* Security descriptor. Only relevant to servers */
        -1,       /* Nr. of auth services. Only relevant to servers */
        NULL,     /* List of auth services. Only relevant to servers */
        NULL,     /* Reserved */
        RPC_C_AUTHN_LEVEL_DEFAULT, /* Default authentication.  The
                                        details don't really matter when
                                        you're localhost. */
        RPC_C_IMP_LEVEL_IMPERSONATE, /* WMI needs to be able to
                                        impersonate us. */
        NULL,             /* Authentication info */
        EOAC_NONE,        /* Additional capabilities */
        NULL              /* Reserved */
        );
    if (FAILED(hres)) {
        goto err_out;
    }
            OutputDebugString("CreateInstance\n");
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0, 
            CLSCTX_INPROC_SERVER, 
            IID_IWbemLocator,
            (LPVOID *) &locator);
        OutputDebugString("Check hres\n");
        if (FAILED(hres)) {
            goto err_out;
        }
        if (locator == NULL) {
            OutputDebugString("Null locator");
            goto err_out;
        }
    return true;
err_out:
    return false;
}

BOOL ConnectToWMI(void)
{
        InitCom();
        HRESULT hres;
        OutputDebugString("Connect to WMI");
        wmicount++;

        wmi = (struct WMIAccessor *)XsAlloc(sizeof(*wmi));
        if (wmi == NULL) {
            return false;
        }
        memset(wmi, 0, sizeof(*wmi));


        OutputDebugString("Connect Server\n");
        try {
            hres = locator->ConnectServer(
                L"root\\CIMV2",          // WMI namespace
                NULL,                    // User name
                NULL,                    // User password
                NULL,                    // Locale
                0,                       // Security flags
                NULL,                    // Authority
                NULL,                    // Context object
                &(wmi->mpSvc)              // IWbemServices proxy
                );
        }
        catch(...) {
            OutputDebugString("Exception connecting to server\n");
            goto err_out;
        }

        OutputDebugString("Check result\n");
        if (FAILED(hres)) {
            goto err_out;
        }
        /* WMI needs to impersonate us, because it normally runs as an
           unprivileged user and needs our authority in order to access
           device files and so forth.  Turn impersonation on. */
        OutputDebugString("Proxy blanket\n");
        hres = CoSetProxyBlanket(
            wmi->mpSvc,                  // the proxy to set
            RPC_C_AUTHN_WINNT,           /* LAN manager authentication,
                                            although it doesn't really
                                            matter on localhost. */
            RPC_C_AUTHZ_NONE,            // LANMAN can't do much authorization.
            NULL,                        // Server principal name
            RPC_C_AUTHN_LEVEL_CALL,      // Do authentication on every call
            RPC_C_IMP_LEVEL_IMPERSONATE, // Allow full impersonation.
            NULL,                        // Use current client identity
            EOAC_NONE                    // No extended proxy capabilities
        );
        if (FAILED(hres)) {
            goto err_out;
        }
        OutputDebugString("WMI Server\n");
        hres = locator->ConnectServer(
            L"root\\WMI",          // WMI namespace
            NULL,                    // User name
            NULL,                    // User password
            NULL,                    // Locale
            0,                       // Security flags
            NULL,                    // Authority
            NULL,                    // Context object
            &wmi->mpXSSvc              // IWbemServices proxy
            );

        if (FAILED(hres)) {
            goto err_out;
        }
        OutputDebugString("Impersonation\n");
        /* WMI needs to impersonate us, because it normally runs as an
           unprivileged user and needs our authority in order to access
           device files and so forth.  Turn impersonation on. */
        hres = CoSetProxyBlanket(
            wmi->mpXSSvc,                  // the proxy to set
            RPC_C_AUTHN_WINNT,           /* LAN manager authentication,
                                            although it doesn't really
                                            matter on localhost. */
            RPC_C_AUTHZ_NONE,            // LANMAN can't do much authorization.
            NULL,                        // Server principal name
            RPC_C_AUTHN_LEVEL_CALL,      // Do authentication on every call
            RPC_C_IMP_LEVEL_IMPERSONATE, // Allow full impersonation.
            NULL,                        // Use current client identity
            EOAC_NONE                    // No extended proxy capabilities
        );
        if (FAILED(hres)) {
            goto err_out;
        }


    OutputDebugString("Wmi connected\n");
    /* All done. */
    return true;

err_out:
    OutputDebugString("WMI connection failed\n");
    ReleaseWMIAccessor(&wmi);
    return false;
}


void ReleaseCom(void) {

    if (com_initialized) {
        OutputDebugString("Release locator\n");
        locator->Release();
        //XsLog("Wmi disconnect thread %p", GetCurrentThread());
        //ASSERT((*wmi)->owning_thread == GetCurrentThread());
        com_initialized = 0;
        OutputDebugString("Uninitialize com\n");
        CoUninitialize();
        
    }
}

/* Careful: WMI accessors must be released on the same thread that
   allocated them. */
void ReleaseWMIAccessor(struct WMIAccessor **wmi)
{
    OutputDebugString("Should I release wmi?\n");
    if (*wmi == NULL)
        return;
    OutputDebugString("Get rid of WMI servers\n");
    if ((*wmi)->mpXSSvc != NULL)
        (*wmi)->mpXSSvc->Release();
    if ((*wmi)->mpSvc != NULL)
        (*wmi)->mpSvc->Release();
    OutputDebugString("Clear WmI\n");
    /* Poison wmi to make use-after-free()s a bit more obvious. */
    memset((*wmi), 0xab, sizeof(**wmi));
    XsFree(*wmi);
    *wmi = NULL;
    ReleaseCom();
    OutputDebugString("Released WMI\n");
}

/* The fact that something is documented as being a uint64_t field
   doesn't imply that it will be returned as a VT_UI8 field in a
   variant structure.  Work around this with a handy conversion
   function. */
static uint64_t
GetVariantUint64(VARIANT *vtData)
{
    switch (vtData->vt) {
    case VT_I2:
        return vtData->iVal;
    case VT_I4:
        return vtData->lVal;
    case VT_I8:
        return vtData->llVal;
    case VT_UI2:
        return vtData->uiVal;
    case VT_UI4:
        return vtData->ulVal;
    case VT_UI8:
        return vtData->ullVal;
    case VT_BSTR:
        /* Yes, I really do mean BSTR: XP returns 64 bit values as
           strings, and we then have to do atoill on it. */
        return _wtoi64(vtData->bstrVal);
    default:
        DBGPRINT(("Bad uint64_t variant %d.\n",vtData->vt));
        return -1;
    }
}

static HRESULT
QueryVariant(WMIAccessor *wmi, PWCHAR field, PWCHAR table, VARIANT *vt)
{
    IEnumWbemClassObject *pEnum;
    BSTR query;
    size_t query_len;
    IWbemClassObject *pclsObj;
    HRESULT hr;
    ULONG uReturn;

    query_len = strlen("SELECT  FROM ") + wcslen(field) + wcslen(table) + 1;
    query = SysAllocStringLen(NULL, (UINT)query_len);
    if (query == NULL) {
        hr = E_OUTOFMEMORY;
        goto err;
    }
    swprintf_s(query, query_len, L"SELECT %s FROM %s", field, table);
    pEnum = runQuery(wmi, query);
    SysFreeString(query);

    if (pEnum == NULL) {
        hr = E_OUTOFMEMORY;
        goto err;
    }

    hr = pEnum->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    pEnum->Release();
    if (FAILED(hr))
        goto err;
    if (uReturn == 0) {
        hr = E_FAIL;
        goto err;
    }

    hr = pclsObj->Get(field, 0, vt, NULL, NULL);
    pclsObj->Release();

    return hr;

err:
    return hr;
}

static uint64_t
QueryUint64(WMIAccessor *wmi, PWCHAR field, PWCHAR table)
{
    HRESULT hr;
    uint64_t res;
    VARIANT vt;

    memset(&vt, 0, sizeof(vt));

    hr = QueryVariant(wmi, field, table, &vt);
    if (FAILED(hr))
        return 0;

    res = GetVariantUint64(&vt);
    VariantClear(&vt);
    return res;
}

static BSTR
QueryBstr(WMIAccessor *wmi, PWCHAR field, PWCHAR table)
{
    HRESULT hr;
    VARIANT vt;

    memset(&vt, 0, sizeof(vt));

    hr = QueryVariant(wmi, field, table, &vt);
    if (FAILED(hr))
        return NULL;
    if (vt.vt != VT_BSTR) {
        VariantClear(&vt);
        return NULL;
    }
    return vt.bstrVal;
}



/* hash comparator for strings which strips off trailing .exe
 * suffix */
class string_eq_exe {
private:
    static size_t len_without_suffix(const char *x)
    {
        size_t l;
        l = strlen(x);
        if (l > 4 && !strcmp(x + l - 4, ".exe"))
            l -= 4;
        return l;
    }

public:
    enum {bucket_size = 4, min_buckets = 8};
    bool operator()(const string &a, const string &b) const
    {
        const char *a_c, *b_c;
        size_t a_l, b_l;
        a_c = a.c_str();
        b_c = b.c_str();
        a_l = len_without_suffix(a_c);
        b_l = len_without_suffix(b_c);

        if (a_l != b_l)
            return 1;
        if (memcmp(a_c, b_c, a_l))
            return 1;
        else
            return 0;
    }

    size_t operator()(const string &a) const
    {
        size_t acc = 0;
        const char *c_str = a.c_str();
        size_t len = len_without_suffix(c_str);
        unsigned x;
        for (x = 0; x < len; x++)
            acc = (acc * 17 + c_str[x]) % 257;
        return acc;
    }
};


IWbemClassObject *getBase(WMIAccessor** wmi) 
{
    IWbemClassObject* base = getObject(wmi, OBJECT_NAME_W(Base));
    if (base == NULL) {
        *wmi = NULL;
        return NULL;
    }
    return base;
}

IWbemClassObject *getBaseClass(WMIAccessor** wmi) 
{
    IWbemClassObject* baseclass = getClass(wmi, OBJECT_NAME_W(Base));
    if (baseclass == NULL) {
        *wmi = NULL;
        return NULL;
    }
    return baseclass;
}

ULONGLONG get64BitUnsigned(VARIANT *var) {
    ULONGLONG res = 0;
    switch (var->vt) {
        case VT_BSTR: {
                VARIANT outvar;
                VariantInit(&outvar);
                VariantChangeType(&outvar, var, 0, VT_UI8);
                res = outvar.ullVal;
                VariantClear(&outvar);
            }
            break;
        case VT_UI8: {
                res = var->ullVal;
            }
            break;
    }
    return res;
}

FILETIME WmiGetXenTime(WMIAccessor **wmi) {
     FILETIME out;
     
     IWbemClassObject *base = getBase(wmi);
     if (base == NULL) {
         DBGPRINT(("Unable to find base WMI session\n"));
         goto getbasefailed;
     }

     VARIANT timevar;
     BSTR timename = mkBstr("XenTime", 7);
     if (timename == NULL)
         goto buildtimenamefailed;
         


     if (FAILED(base->Get(timename, 0, &timevar, NULL, NULL)))
         goto gettimefailed;

     ULONGLONG time =get64BitUnsigned(&timevar);;

     out.dwLowDateTime = (DWORD)time;
     out.dwHighDateTime = (DWORD)(time>>32);
     return out;

gettimefailed:
buildtimenamefailed:
getbasefailed:
     out.dwLowDateTime = 0;
     out.dwHighDateTime = 0;
     return out ;
}

IWbemClassObject *openSession(WMIAccessor** wmi, const char *sessionname)
{
    HRESULT hres;

    BSTR query = formatBstr("SELECT * FROM " OBJECT_NAME_A(Session) " WHERE Id=\"" OBJECT_PREFIX_STR " Xen Win32 Service : %s\"", sessionname);
    if (query == NULL)
        goto formatsessionbstrfailed;

    IEnumWbemClassObject * sessions = runXSQuery(wmi, query);
    SysFreeString(query);

    if (sessions) {
        IWbemClassObject *returnedObject;
        ULONG count;
        hres = sessions->Next(WBEM_INFINITE, 1, &returnedObject, &count);
        sessions->Release();

        if (count>0) {
            if (sessionname !=NULL ) {
                if (!WmiSessionEnd(wmi, returnedObject)) {
                    return NULL;
                }
            }
            else {
                return returnedObject;
            }
        }
    }

    IWbemClassObject *base = getBase(wmi);
    if (base==NULL) {
        DBGPRINT(("Unable to find base WMI session\n"));
        goto getbasefailed;
    }

    IWbemClassObject *baseclass = getBaseClass(wmi);

    if (baseclass == NULL)
        goto getbaseclassfailed;

    IWbemClassObject *inMethod;

    IWbemClassObject *inMethodInst;
    IWbemClassObject *outMethodInst;
    if (FAILED(baseclass->GetMethod(L"AddSession",0,&inMethod, NULL)))
        goto getmethodaddsessionfailed;

    if (FAILED(inMethod->SpawnInstance(0, &inMethodInst)))
        goto inmethodspawnfailed;

    VARIANT var;
    var.vt = VT_BSTR;
    var.bstrVal=formatBstr(VENDOR_NAME_STR " " PRODUCT_NAME_STR " Win32 Service : %s", sessionname);

    if (var.bstrVal == NULL)
        goto formatnamebstrfailed;

    if (FAILED(inMethodInst->Put(L"Id", 0, &var, 0)))
        goto methodputfailed;

    if (FAILED(methodExec(wmi, base, L"AddSession", inMethodInst, &outMethodInst)))
        goto methodexecaddsessionfailed;
    
    if (FAILED(outMethodInst->Get(L"SessionId", 0, &var, NULL, NULL)))
        goto outmethodgetfailed;

    size_t query_len;
    query_len = strlen("SELECT * FROM " OBJECT_NAME_A(Session) " WHERE SessionId=")+10;
    query = SysAllocStringLen(NULL, (UINT)query_len);

    if (query == NULL)
        goto allocqueryfailed;

    swprintf_s(query,query_len, L"SELECT * FROM " OBJECT_NAME_W(Session) L" WHERE SessionId=%d", var.uintVal);

    sessions = runXSQuery(wmi, query );
    SysFreeString(query);

    if (sessions) {
        IWbemClassObject *returnedObject;
        ULONG count;
        hres = sessions->Next(WBEM_INFINITE, 1, &returnedObject, &count);
        sessions->Release();
        if (count>0) {
            return returnedObject;
        }
        
    }
    
    outMethodInst->Release();
    VariantClear(&var);
    inMethodInst->Release();
    inMethod->Release();
    base->Release();
    baseclass->Release();
    return NULL;

allocqueryfailed:
outmethodgetfailed:
    outMethodInst->Release();

methodexecaddsessionfailed:
methodputfailed:
    VariantClear(&var);

formatnamebstrfailed:
    inMethodInst->Release();
inmethodspawnfailed:
    inMethod->Release();


getmethodaddsessionfailed:
    baseclass->Release();

getbaseclassfailed:
    base->Release();

getbasefailed:


formatsessionbstrfailed:
    return NULL;
}

IWbemClassObject* sessionMethodStart(WMIAccessor**wmi,  
                                     const wchar_t *methodname)
{
    IWbemClassObject *inMethod;
    IWbemClassObject *inMethodInst = NULL;
    IWbemClassObject *sessionClass;
    HRESULT hr;

    ASSERT(wmi != NULL);

    sessionClass = getClass(wmi, OBJECT_NAME_W(Session));
    if (sessionClass == NULL)
        goto getclassfailed;

    hr = sessionClass->GetMethod(methodname,0,&inMethod, NULL);
    if (FAILED(hr))
        goto getmethodfailed;

    hr = inMethod->SpawnInstance(0, &inMethodInst);
    if (FAILED(hr))
        goto spawninstancefailed;

    inMethod->Release();

    sessionClass->Release();
    return inMethodInst;


spawninstancefailed:
    inMethod->Release();
    
getmethodfailed:
    sessionClass->Release();

getclassfailed:
    return NULL;
}


char * bstrToChar(BSTR bst, size_t *len) {
    *len = wcslen(bst);
    char *space = (char *)XsAlloc(*len+1);
    if (space)
        wcstombs_s(len, space, *len+1, bst,  _TRUNCATE);
    return space;
}

void WmiSessionLog(WMIAccessor** wmi,  void **sessionhandle,const char *fmt, va_list args) {
    IWbemClassObject **session = (IWbemClassObject **)sessionhandle;
    
    char* message = formatCharStrInt(fmt,args);
    
    OutputDebugString(message);
    if (((*wmi)==NULL) || ((*sessionhandle)==NULL) ) {
        goto nowmi;
    }
    VARIANT vmessage;
    if (setVariantString(&vmessage, message))
        goto setvmessage;

    IWbemClassObject *inMethodInst = sessionMethodStart( wmi, L"Log");
    if (!inMethodInst)
        goto sessionstart;
    
     if (FAILED(inMethodInst->Put(L"Message",0,&vmessage,0)))
         goto methodputfailed;

     if (FAILED(methodExec(wmi,*session, L"Log", inMethodInst, NULL)))
         goto methodexecfailed;

methodexecfailed:
methodputfailed:
     inMethodInst->Release();

sessionstart:
    VariantClear(&vmessage);

setvmessage:
nowmi:
    return;
}

char* WmiSessionGetEntry(WMIAccessor** wmi, void **sessionhandle,
              const char * path, size_t* len) 
{
    *len = 0;
    IWbemClassObject **session = (IWbemClassObject **)sessionhandle;

    VARIANT vpath;
    if (setVariantString(&vpath, path))
        goto setvpath;

    IWbemClassObject *outMethodInst = NULL;

    IWbemClassObject *inMethodInst = sessionMethodStart( wmi, L"GetValue");
    if (inMethodInst == NULL) 
        goto sessionmethodstartfailed;
    
    if (FAILED(inMethodInst->Put(L"PathName",0,&vpath,0))) 
        goto methodexecfailed;

    methodExec(wmi,*session, L"GetValue", inMethodInst, &outMethodInst);
    if (outMethodInst==NULL)
        goto sessionExec;

    VARIANT outval;
    VariantInit(&outval);

    if (FAILED(outMethodInst->Get(L"value", 0, &outval, NULL, NULL)))
        goto methodgetfailed;

    char *space = NULL;
    
    if (V_VT(&outval) == VT_BSTR) 
    {
        space = bstrToChar(outval.bstrVal, len);
    }

    outMethodInst->Release();
    inMethodInst->Release();
    VariantClear(&vpath);
    VariantClear(&outval); 
    return space;

methodgetfailed:
    outMethodInst->Release();

methodexecfailed:
sessionExec:
    inMethodInst->Release();

sessionmethodstartfailed:
    VariantClear(&vpath);

setvpath:
    return NULL;
}

int WmiSessionSetEntry(WMIAccessor** wmi,  void **sessionhandle, 
              const char*path, const char * value, size_t len)
{
    int err = -1;
    IWbemClassObject **session = (IWbemClassObject **)sessionhandle;

    VARIANT vpath;
    if (setVariantString(&vpath, path))
        goto setvpath;

    VARIANT vvalue;
    if (setVariantString(&vvalue, value))
        goto setvvalue;

    IWbemClassObject *outMethodInst;

    IWbemClassObject *inMethodInst = sessionMethodStart( wmi, L"SetValue");
    if (!inMethodInst)
        goto sessionstart;

    inMethodInst->Put(L"PathName",0,&vpath,0);
    inMethodInst->Put(L"value",0,&vvalue,0);

    if (FAILED(methodExec(wmi,*session, L"SetValue", inMethodInst, &outMethodInst)))
        goto methodexecfailed;

    if (outMethodInst!=NULL) 
        outMethodInst->Release();

    inMethodInst->Release();
    SysFreeString(vvalue.bstrVal);
    SysFreeString(vpath.bstrVal);

    return 0;

methodexecfailed:
    XsLog("WmiSessionSetEntry:MethodExec Failed");
    inMethodInst->Release();

sessionstart:
    XsLog("WmiSessionSetEntry:SessionStart Failed");
    SysFreeString(vvalue.bstrVal);

setvvalue:
    XsLog("WmiSessionSetEntry:SetVValue Failed");
    SysFreeString(vpath.bstrVal);

setvpath:
    XsLog("WmiSessionSetEntry:SetVPath Failed ");
    return err;
}

int WmiSessionSetEntry(WMIAccessor** wmi,  void **sessionhandle, 
              const char*path, const char * value) {
    return WmiSessionSetEntry(wmi, sessionhandle, path, value, strlen(value));
}

int WmiSessionRemoveEntry(WMIAccessor** wmi,  void **sessionhandle, 
              const char*path){

    int err = -1;
    IWbemClassObject **session = (IWbemClassObject **)sessionhandle;

    VARIANT vpath;
    if (setVariantString(&vpath, path))
        goto setvpath;

    IWbemClassObject *inMethodInst = sessionMethodStart( wmi, L"RemoveValue");
    if (!inMethodInst)
        goto sessionstart;

    if (FAILED(inMethodInst->Put(L"PathName",0,&vpath,0)))
        goto methodputfailed;

    IWbemClassObject* outMethodInst;

    if (FAILED(methodExec(wmi,*session, L"RemoveValue", inMethodInst, &outMethodInst)))
        goto methodexecfailed;

    if (outMethodInst != NULL)
        outMethodInst->Release();

    err=0;
    inMethodInst->Release();
    VariantClear(&vpath);
    return err;
methodexecfailed:
    OutputDebugString(__FUNCTION__ " MethodExecFailed");
methodputfailed:
    OutputDebugString(__FUNCTION__ " MethodPutFailed");
    inMethodInst->Release();

sessionstart:
    OutputDebugString(__FUNCTION__ " SessionStartFailed");
    VariantClear(&vpath);

    OutputDebugString(__FUNCTION__ " SessionExecFailed");
setvpath:
    OutputDebugString(__FUNCTION__ " SetVpathFailed");
    return err; 
}


BOOL WmiSessionUnwatch(WMIAccessor** wmi,  void **sessionhandle,
                         void *watchhandle) {
    IWbemClassObject **session = (IWbemClassObject **)sessionhandle;
    XsLog("Unwatch %p",watchhandle);
    WatchSink * sink = (WatchSink *)watchhandle;

    VARIANT vpath;
    if (setVariantString(&vpath, sink->path))
        goto setvpath;

    IWbemClassObject *outMethodInst;
    IWbemClassObject *inMethodInst = sessionMethodStart( wmi, L"RemoveWatch");
    if (!inMethodInst)
        goto sessionstart;

    inMethodInst->Put(L"PathName",0,&vpath,0);
    if FAILED(methodExec(wmi,*session, L"RemoveWatch", inMethodInst, &outMethodInst))
        goto methodexecfailed;
    if (outMethodInst==NULL)
        goto sessionexecfailed;

    outMethodInst->Release();

methodexecfailed:
sessionexecfailed:
    inMethodInst->Release();

sessionstart:
setvpath:
    sink->Release();
    return true;
}

BOOL WmiSessionStart(WMIAccessor** wmi,  void **sessionhandle, const char* sessionname) 
{
    IWbemClassObject **session = (IWbemClassObject **)sessionhandle;
    if ((*session = openSession(wmi, sessionname)) == NULL) {
        return false;
    }
    return true;
}


BOOL WmiSessionEnd(WMIAccessor** wmi,  void *sessionhandle) 
{
    HRESULT hr;
    ASSERT(*wmi != NULL);

    IWbemClassObject *session = (IWbemClassObject *)sessionhandle;
    if (session==NULL) {
        return false;
    }
    hr = methodExec(wmi, session, L"EndSession", NULL,NULL);
    if FAILED(hr)
        goto execmethodfailed;
    session->Release();
    return true;

execmethodfailed:
    return false;

}

void *WmiSessionWatch(WMIAccessor** wmi,  void **sessionhandle, 
                      const char *path, HANDLE event, HANDLE errorevent) {
       
    HRESULT hr;

    IWbemClassObject **session = (IWbemClassObject **)sessionhandle;
    
    ASSERT((*wmi) != NULL);
    ASSERT((*sessionhandle) != NULL);

    WatchSink * sink = new WatchSink(event, errorevent, path);
    BSTR query=formatBstr("SELECT * from " OBJECT_NAME_A(WatchEvent) " WHERE EventId=\"%s\"", path);
    if (query == NULL) {
        goto formatstringfailed;
    }

    hr = (*wmi)->mpXSSvc->ExecNotificationQueryAsync(L"WQL", query,0,NULL, sink);
    if (FAILED(hr)){
        *wmi = NULL;
        goto wmifailed;
    }

    VARIANT vpath;
    if (setVariantString(&vpath, path)){
        goto setvpath;
    }


    IWbemClassObject *inMethodInst = sessionMethodStart( wmi, L"SetWatch");
    if (!inMethodInst)
        goto sessionstart;

    hr = inMethodInst->Put(L"PathName",0,&vpath,0);
    if (FAILED(hr))
        goto methodputfailed;

    hr = methodExec(wmi,*session, L"SetWatch", inMethodInst, NULL);
    if (FAILED(hr))
        goto methodexecfailed;

    VariantClear(&vpath);

    SysFreeString(query);

    return sink;


methodexecfailed:
    OutputDebugString(__FUNCTION__ " : methodexecfailed\n");
methodputfailed:
    OutputDebugString(__FUNCTION__ " : methodputfailed\n");
    inMethodInst->Release();
sessionstart:
    OutputDebugString(__FUNCTION__ " : sessionstart\n");
    VariantClear(&vpath);
setvpath:
    OutputDebugString(__FUNCTION__ " : setvpath\n");
wmifailed:
    SysFreeString(query);
formatstringfailed:
    OutputDebugString(__FUNCTION__ " : formatstringfailed\n");
    delete sink;
    return NULL;
}

void *WmiUnsuspendedEventWatch(WMIAccessor **wmi, HANDLE event, HANDLE errorevent) 
{
    HRESULT hr;

    ASSERT(*wmi != NULL);

    WatchSink * sink = new WatchSink(event, errorevent, NULL);
    BSTR query=formatBstr("SELECT * from " OBJECT_NAME_A(UnsuspendedEvent));
    if (query==NULL) {
        goto formatstringfailed;
    }

    hr = (*wmi)->mpXSSvc->ExecNotificationQueryAsync(L"WQL", query,0,NULL, sink);
    if FAILED(hr)
        goto asyncqueryfailed;

    SysFreeString(query);
    return sink;

asyncqueryfailed:
    SysFreeString(query);
formatstringfailed:
    delete sink;
    return NULL;
}

