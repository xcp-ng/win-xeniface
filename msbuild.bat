call "%VS%\VC\vcvarsall.bat" x86
@echo on
msbuild.exe /p:Configuration="%CONFIGURATION%" /p:Platform="%PLATFORM%" /t:"%TARGET%" %EXTRA% %FILE%

