rem testwmi.vbs

rem Copyright (c) Citrix Systems Inc.
rem All rights reserved.
rem
rem Redistribution and use in source and binary forms, 
rem with or without modification, are permitted provided 
rem that the following conditions are met:
rem
rem *   Redistributions of source code must retain the above 
rem     copyright notice, this list of conditions and the 
rem     following disclaimer.
rem *   Redistributions in binary form must reproduce the above 
rem     copyright notice, this list of conditions and the 
rem     following disclaimer in the documentation and/or other 
rem     materials provided with the distribution.
rem
rem THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
rem CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
rem INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
rem MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
rem DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
rem CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
rem SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
rem BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
rem SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
rem INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
rem WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
rem NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
rem OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
rem SUCH DAMAGE.

rem a sanity check for the xeniface wmi interface
rem can be called using cscript.exe
rem will set %ERRORLEVEL% to 0 on success and 1 on failure
rem will also output the text 'SUCCESS' or an error message

Set objWMIService = GetObject("winmgmts:\\.\root\wmi")
Set base = objWmiService.InstancesOf("CitrixXenStoreBase")
Dim answer
Dim answer2
Dim objItem


rem Locate the base object

if (base.Count) <> 1 then
    wscript.echo("Too many base objects found")
    wscript.quit(1)
end if
for each itementry in base
  rem is there a more trivial way of getting the only item from a collection in vbscript?
  set objItem = itementry
next
  
rem Add two sessions

objitem.AddSession "VBSTestSession", answer
objitem.AddSession "AnotherVBSTestSession", answer2

rem locate the first session

query = "select * from CitrixXenStoreSession where SessionId = '" & answer & "'"
Set sessions = objWMIService.ExecQuery(query)  
if (sessions.count) <> 1 then
    wscript.echo("Too many session-1 sessions found")
    wscript.quit(1)
end if
for each itementry in sessions
  rem is there a more trivial way of getting the only item from a collection in vbscript?
  set session = itementry
next

rem locate te second session

query = "select * from CitrixXenStoreSession where SessionId = '" & answer2 & "'"
Set sessions2 = objWMIService.ExecQuery(query)
if (sessions2.count) <> 1 then
    wscript.echo("Too many session-2 sessions found")
    wscript.quit(1)
end if
dim session2
for each ses in sessions2
  Set session2=ses
next

rem ensure we located the expected session

if session.Id <> "VBSTestSession" then
  wscript.echo("incorrect session found")
  wscript.quit(1)
end if

rem blank a set of xenstore entries

session.removevalue "data/wmitestrun"

rem and put a known set of values there

session.SetValue "data/wmitestrun/test1", "Testing"
session.SetValue "data/wmitestrun/test2", "123 Testing"
session.SetValue "data/wmitestrun/test3", "456 Testing"
session.SetValue "data/wmitestrun/test4", "789 Testing"

rem read back a value from xenstore, and check that it is right

session.getvalue "data/wmitestrun/test1", res
if res <> "Testing" then
  wscript.echo("failed writing or reading to data/wmitestrun/test1")
  wscript.echo("read = " & res)
  wscript.quit(1)
end if 

rem read back a different value from xenstore, and check that it is right

session.getvalue "data/wmitestrun/test2", res
if res <> "123 Testing" then
  wscript.echo("failed writing or reading to data/wmitestrun/test2")
  wscript.echo("read = " & res)
  wscript.quit(1)
end if 

rem transactions
rem test that aborted transactions don't do anything

session.starttransaction()
session.SetValue "data/wmitestrun/test1", "WEIRD"
session.getvalue "data/wmitestrun/test1", res
if res <> "WEIRD" then
  wscript.echo("failed writing or reading within transaction to data/wmitestrun/test1")
  wscript.echo("read = " & res)
  wscript.quit(1)
end if 
session.aborttransaction()

session.getvalue "data/wmitestrun/test1", res
if res <> "Testing" then
  wscript.echo("failed reading to data/wmitestrun/test1 after aborted transaction ")
  wscript.echo("read = " & res)
  wscript.quit(1)
end if


rem test that 2 overlapping transactions honour commits and aborts, and raise errors when needed

session.starttransaction()
session2.starttransaction()
session.SetValue "data/wmitestrun/test1", "WEIRD"
session2.SetValue "data/wmitestrun/test1", "Fish"
session.getvalue "data/wmitestrun/test1", res
session2.getvalue "data/wmitestrun/test1", res2
if res <> "WEIRD" then
  wscript.echo("failed writing or reading within transaction to data/wmitestrun/test1 session 1")
  wscript.echo("read = " & res)
  wscript.quit(1)
end if 
if res2 <> "Fish" then
  wscript.echo("failed writing or reading within transaction to data/wmitestrun/test1 session 2")
  wscript.echo("read = " & res)
  wscript.quit(1)
end if 

on error resume next
session.committransaction()
Err.clear()
if Err.Number <> 0 then
    wscript.echo("Could not commit first transaction")
    wscript.quit(1)
end if
session2.committransaction() 
if Err.Number = 0 then
    wscript.echo("Both transactions comitted")
    wscript.quit(1)
end if
session2.aborttransaction()
session2.getvalue "data/wmitestrun/test1", res2
if res2 <> "WEIRD" then
  wscript.echo("failed commiting the correct transaction")
  wscript.echo("read = " & res)
  wscript.quit(1)
end if 

rem events
rem set up an event sink

dim refsink
set refsink = CreateObject("WBemScripting.SWbemSink")
wscript.ConnectObject refsink, "EVENTSINK_"
stq = "Select * from CitrixXenStoreWatchEvent"
objwmiservice.ExecNotificationQueryAsync refsink, stq

evtcount = 0

rem watch a xenstore entry

allevents=0
session.setwatch "data/wmitestrun/test1"
session.setvalue "data/wmitestrun/test1","MAGIC"
session.removevalue "data/wmitestrun/test1"
session.setvalue "data/wmitestrun/test1","GOLD"
wscript.sleep(5000)
session.removewatch "data/wmitestrun/test1"

rem check we received an event.  Also, since events can be coalesced, check
rem that when we receive our final event, the value we read from test1 is the
rem final value we set it to

rem (note the actual work of counting and checking events is done in the 
rem EVENTSINK_OnObjectready sub below)

if evtcount <= 4 and allevents <> 1 then
    wscript.echo("Failed to catch all the expected events")
    wscript.quit(1)
end if

session.removevalue "data/wmitestrun/test1"

rem check that we can read the list of children an entry has

strComputer = "."
Set objWMIService = GetObject("winmgmts:" _
    & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")

Set colOperatingSystems = objWMIService.ExecQuery _
    ("Select * from Win32_OperatingSystem")

for each os in colOperatingSystems
  rem is there a more trivial way of getting the only item from a collection in vbscript?
  set myos = os
next

wscript.echo(myos.Version)

if Mid(myos.Version, 1 , 3) <> "6.0" then

    dim children
    session.getchildren "data/wmitestrun", children

    if children.noofchildnodes <> 3 then
        wscript.echo("Failed to find all the expected child nodes")
        wscript.quit(1)
    end if
end if

session.getfirstchild "data/wmitestrun", res
session.getnextsibling res, res

rem end both sessions that we created.

session2.EndSession()
session.EndSession()

Wscript.echo("Success")

Sub EVENTSINK_OnObjectReady(re, rc)
   evtcount = evtcount + 1
   session.getvalue "data/wmitestrun/test1", res
   if res = "GOLD" then
       allevents = 1
   else
       allevents = 0
   end if
end sub
